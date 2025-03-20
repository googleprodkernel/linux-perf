#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
from metric import (d_ratio, has_event, max, CheckPmu, Event, JsonEncodeMetric,
                    JsonEncodeMetricGroupDescriptions, Literal, LoadEvents,
                    Metric, MetricConstraint, MetricGroup, MetricRef, Select)
import argparse
import json
import math
import os
import re
from typing import Optional

# Global command line arguments.
_args = None
interval_sec = Event("duration_time")

def Idle() -> Metric:
  cyc = Event("msr/mperf/")
  tsc = Event("msr/tsc/")
  low = max(tsc - cyc, 0)
  return Metric(
      "idle",
      "Percentage of total wallclock cycles where CPUs are in low power state (C1 or deeper sleep state)",
      d_ratio(low, tsc), "100%")


def Rapl() -> MetricGroup:
  """Processor power consumption estimate.

  Use events from the running average power limit (RAPL) driver.
  """
  # Watts = joules/second
  pkg = Event("power/energy\-pkg/")
  cond_pkg = Select(pkg, has_event(pkg), math.nan)
  cores = Event("power/energy\-cores/")
  cond_cores = Select(cores, has_event(cores), math.nan)
  ram = Event("power/energy\-ram/")
  cond_ram = Select(ram, has_event(ram), math.nan)
  gpu = Event("power/energy\-gpu/")
  cond_gpu = Select(gpu, has_event(gpu), math.nan)
  psys = Event("power/energy\-psys/")
  cond_psys = Select(psys, has_event(psys), math.nan)
  scale = 2.3283064365386962890625e-10
  metrics = [
      Metric("cpu_power_pkg", "",
             d_ratio(cond_pkg * scale, interval_sec), "Watts"),
      Metric("cpu_power_cores", "",
             d_ratio(cond_cores * scale, interval_sec), "Watts"),
      Metric("cpu_power_ram", "",
             d_ratio(cond_ram * scale, interval_sec), "Watts"),
      Metric("cpu_power_gpu", "",
             d_ratio(cond_gpu * scale, interval_sec), "Watts"),
      Metric("cpu_power_psys", "",
             d_ratio(cond_psys * scale, interval_sec), "Watts"),
  ]

  return MetricGroup("cpu_power", metrics,
                     description="Running Average Power Limit (RAPL) power consumption estimates")


def Smi() -> MetricGroup:
    aperf = Event('msr/aperf/')
    cycles = Event('cycles')
    smi_num = Event('msr/smi/')
    smi_cycles = Select(Select((aperf - cycles) / aperf, smi_num > 0, 0),
                        has_event(aperf),
                        0)
    return MetricGroup('smi', [
        Metric('smi_num', 'Number of SMI interrupts.',
               Select(smi_num, has_event(smi_num), 0), 'SMI#'),
        # Note, the smi_cycles "Event" is really a reference to the metric.
        Metric('smi_cycles',
               'Percentage of cycles spent in System Management Interrupts. '
               'Requires /sys/devices/cpu/freeze_on_smi to be 1.',
               smi_cycles, '100%', threshold=(MetricRef('smi_cycles') > 0.10))
    ], description = 'System Management Interrupt metrics')


def Tsx() -> Optional[MetricGroup]:
  pmu = "cpu_core" if CheckPmu("cpu_core") else "cpu"
  cycles = Event('cycles')
  cycles_in_tx = Event(f'{pmu}/cycles\-t/')
  cycles_in_tx_cp = Event(f'{pmu}/cycles\-ct/')
  try:
    # Test if the tsx event is present in the json, prefer the
    # sysfs version so that we can detect its presence at runtime.
    transaction_start = Event("RTM_RETIRED.START")
    transaction_start = Event(f'{pmu}/tx\-start/')
  except:
    return None

  elision_start = None
  try:
    # Elision start isn't supported by all models, but we'll not
    # generate the tsx_cycles_per_elision metric in that
    # case. Again, prefer the sysfs encoding of the event.
    elision_start = Event("HLE_RETIRED.START")
    elision_start = Event(f'{pmu}/el\-start/')
  except:
    pass

  return MetricGroup('transaction', [
      Metric('tsx_transactional_cycles',
             'Percentage of cycles within a transaction region.',
             Select(cycles_in_tx / cycles, has_event(cycles_in_tx), 0),
             '100%'),
      Metric('tsx_aborted_cycles', 'Percentage of cycles in aborted transactions.',
             Select(max(cycles_in_tx - cycles_in_tx_cp, 0) / cycles,
                    has_event(cycles_in_tx),
                    0),
             '100%'),
      Metric('tsx_cycles_per_transaction',
             'Number of cycles within a transaction divided by the number of transactions.',
             Select(cycles_in_tx / transaction_start,
                    has_event(cycles_in_tx),
                    0),
             "cycles / transaction"),
      Metric('tsx_cycles_per_elision',
             'Number of cycles within a transaction divided by the number of elisions.',
             Select(cycles_in_tx / elision_start,
                    has_event(elision_start),
                    0),
             "cycles / elision") if elision_start else None,
  ], description="Breakdown of transactional memory statistics")


def IntelBr():
  ins = Event("instructions")

  def Total() -> MetricGroup:
    br_all = Event ("BR_INST_RETIRED.ALL_BRANCHES", "BR_INST_RETIRED.ANY")
    br_m_all = Event("BR_MISP_RETIRED.ALL_BRANCHES",
                     "BR_INST_RETIRED.MISPRED",
                     "BR_MISP_EXEC.ANY")
    br_clr = None
    try:
      br_clr = Event("BACLEARS.ANY", "BACLEARS.ALL")
    except:
      pass

    br_r = d_ratio(br_all, interval_sec)
    ins_r = d_ratio(ins, br_all)
    misp_r = d_ratio(br_m_all, br_all)
    clr_r = d_ratio(br_clr, interval_sec) if br_clr else None

    return MetricGroup("br_total", [
        Metric("br_total_retired",
               "The number of branch instructions retired per second.", br_r,
               "insn/s"),
        Metric(
            "br_total_mispred",
            "The number of branch instructions retired, of any type, that were "
            "not correctly predicted as a percentage of all branch instrucions.",
            misp_r, "100%"),
        Metric("br_total_insn_between_branches",
               "The number of instructions divided by the number of branches.",
               ins_r, "insn"),
        Metric("br_total_insn_fe_resteers",
               "The number of resync branches per second.", clr_r, "req/s"
               ) if clr_r else None
    ])

  def Taken() -> MetricGroup:
    br_all = Event("BR_INST_RETIRED.ALL_BRANCHES", "BR_INST_RETIRED.ANY")
    br_m_tk = None
    try:
      br_m_tk = Event("BR_MISP_RETIRED.NEAR_TAKEN",
                      "BR_MISP_RETIRED.TAKEN_JCC",
                      "BR_INST_RETIRED.MISPRED_TAKEN")
    except:
      pass
    br_r = d_ratio(br_all, interval_sec)
    ins_r = d_ratio(ins, br_all)
    misp_r = d_ratio(br_m_tk, br_all) if br_m_tk else None
    return MetricGroup("br_taken", [
        Metric("br_taken_retired",
               "The number of taken branches that were retired per second.",
               br_r, "insn/s"),
        Metric(
            "br_taken_mispred",
            "The number of retired taken branch instructions that were "
            "mispredicted as a percentage of all taken branches.", misp_r,
            "100%") if misp_r else None,
        Metric(
            "br_taken_insn_between_branches",
            "The number of instructions divided by the number of taken branches.",
            ins_r, "insn"),
    ])

  def Conditional() -> Optional[MetricGroup]:
    try:
      br_cond = Event("BR_INST_RETIRED.COND",
                      "BR_INST_RETIRED.CONDITIONAL",
                      "BR_INST_RETIRED.TAKEN_JCC")
      br_m_cond = Event("BR_MISP_RETIRED.COND",
                        "BR_MISP_RETIRED.CONDITIONAL",
                        "BR_MISP_RETIRED.TAKEN_JCC")
    except:
      return None

    br_cond_nt = None
    br_m_cond_nt = None
    try:
      br_cond_nt = Event("BR_INST_RETIRED.COND_NTAKEN")
      br_m_cond_nt = Event("BR_MISP_RETIRED.COND_NTAKEN")
    except:
      pass
    br_r = d_ratio(br_cond, interval_sec)
    ins_r = d_ratio(ins, br_cond)
    misp_r = d_ratio(br_m_cond, br_cond)
    taken_metrics = [
        Metric("br_cond_retired", "Retired conditional branch instructions.",
               br_r, "insn/s"),
        Metric("br_cond_insn_between_branches",
               "The number of instructions divided by the number of conditional "
               "branches.", ins_r, "insn"),
        Metric("br_cond_mispred",
               "Retired conditional branch instructions mispredicted as a "
               "percentage of all conditional branches.", misp_r, "100%"),
    ]
    if not br_m_cond_nt:
      return MetricGroup("br_cond", taken_metrics)

    br_r = d_ratio(br_cond_nt, interval_sec)
    ins_r = d_ratio(ins, br_cond_nt)
    misp_r = d_ratio(br_m_cond_nt, br_cond_nt)

    not_taken_metrics = [
        Metric("br_cond_retired", "Retired conditional not taken branch instructions.",
               br_r, "insn/s"),
        Metric("br_cond_insn_between_branches",
               "The number of instructions divided by the number of not taken conditional "
               "branches.", ins_r, "insn"),
        Metric("br_cond_mispred",
               "Retired not taken conditional branch instructions mispredicted as a "
               "percentage of all not taken conditional branches.", misp_r, "100%"),
    ]
    return MetricGroup("br_cond", [
        MetricGroup("br_cond_nt", not_taken_metrics),
        MetricGroup("br_cond_tkn", taken_metrics),
    ])

  def Far() -> Optional[MetricGroup]:
    try:
      br_far = Event("BR_INST_RETIRED.FAR_BRANCH")
    except:
      return None

    br_r = d_ratio(br_far, interval_sec)
    ins_r = d_ratio(ins, br_far)
    return MetricGroup("br_far", [
        Metric("br_far_retired", "Retired far control transfers per second.",
               br_r, "insn/s"),
        Metric(
            "br_far_insn_between_branches",
            "The number of instructions divided by the number of far branches.",
            ins_r, "insn"),
    ])

  return MetricGroup("br", [Total(), Taken(), Conditional(), Far()],
                     description="breakdown of retired branch instructions")


def IntelCtxSw() -> MetricGroup:
  cs = Event("context\-switches")
  metrics = [
      Metric("cs_rate", "Context switches per second", d_ratio(cs, interval_sec), "ctxsw/s")
  ]

  ev = Event("instructions")
  metrics.append(Metric("cs_instr", "Instructions per context switch",
                        d_ratio(ev, cs), "instr/cs"))

  ev = Event("cycles")
  metrics.append(Metric("cs_cycles", "Cycles per context switch",
                        d_ratio(ev, cs), "cycles/cs"))

  try:
    ev = Event("MEM_INST_RETIRED.ALL_LOADS", "MEM_UOPS_RETIRED.ALL_LOADS")
    metrics.append(Metric("cs_loads", "Loads per context switch",
                          d_ratio(ev, cs), "loads/cs"))
  except:
    pass

  try:
    ev = Event("MEM_INST_RETIRED.ALL_STORES", "MEM_UOPS_RETIRED.ALL_STORES")
    metrics.append(Metric("cs_stores", "Stores per context switch",
                          d_ratio(ev, cs), "stores/cs"))
  except:
    pass

  try:
    ev = Event("BR_INST_RETIRED.NEAR_TAKEN", "BR_INST_RETIRED.TAKEN_JCC")
    metrics.append(Metric("cs_br_taken", "Branches taken per context switch",
                          d_ratio(ev, cs), "br_taken/cs"))
  except:
    pass

  try:
    l2_misses = (Event("L2_RQSTS.DEMAND_DATA_RD_MISS") +
                 Event("L2_RQSTS.RFO_MISS") +
                 Event("L2_RQSTS.CODE_RD_MISS"))
    try:
      l2_misses += Event("L2_RQSTS.HWPF_MISS", "L2_RQSTS.L2_PF_MISS", "L2_RQSTS.PF_MISS")
    except:
      pass

    metrics.append(Metric("cs_l2_misses", "L2 misses per context switch",
                          d_ratio(l2_misses, cs), "l2_misses/cs"))
  except:
    pass

  return MetricGroup("cs", metrics,
                     description = ("Number of context switches per second, instructions "
                                    "retired & core cycles between context switches"))


def IntelFpu() -> Optional[MetricGroup]:
  cyc = Event("cycles")
  try:
    s_64 = Event("FP_ARITH_INST_RETIRED.SCALAR_SINGLE",
                 "SIMD_INST_RETIRED.SCALAR_SINGLE")
  except:
    return None
  d_64 = Event("FP_ARITH_INST_RETIRED.SCALAR_DOUBLE",
               "SIMD_INST_RETIRED.SCALAR_DOUBLE")
  s_128 = Event("FP_ARITH_INST_RETIRED.128B_PACKED_SINGLE",
                "SIMD_INST_RETIRED.PACKED_SINGLE")

  flop = s_64 + d_64 + 4 * s_128

  d_128 = None
  s_256 = None
  d_256 = None
  s_512 = None
  d_512 = None
  try:
    d_128 = Event("FP_ARITH_INST_RETIRED.128B_PACKED_DOUBLE")
    flop += 2 * d_128
    s_256 = Event("FP_ARITH_INST_RETIRED.256B_PACKED_SINGLE")
    flop += 8 * s_256
    d_256 = Event("FP_ARITH_INST_RETIRED.256B_PACKED_DOUBLE")
    flop += 4 * d_256
    s_512 = Event("FP_ARITH_INST_RETIRED.512B_PACKED_SINGLE")
    flop += 16 * s_512
    d_512 = Event("FP_ARITH_INST_RETIRED.512B_PACKED_DOUBLE")
    flop += 8 * d_512
  except:
    pass

  f_assist = Event("ASSISTS.FP", "FP_ASSIST.ANY", "FP_ASSIST.S")
  if f_assist in [
      "ASSISTS.FP",
      "FP_ASSIST.S",
  ]:
    f_assist += "/cmask=1/"

  flop_r = d_ratio(flop, interval_sec)
  flop_c = d_ratio(flop, cyc)
  nmi_constraint = MetricConstraint.GROUPED_EVENTS
  if f_assist.name == "ASSISTS.FP": # Icelake+
    nmi_constraint = MetricConstraint.NO_GROUP_EVENTS_NMI
  def FpuMetrics(group: str, fl: Optional[Event], mult: int, desc: str) -> Optional[MetricGroup]:
    if not fl:
      return None

    f = fl * mult
    fl_r = d_ratio(f, interval_sec)
    r_s = d_ratio(fl, interval_sec)
    return MetricGroup(group, [
        Metric(f"{group}_of_total", desc + " floating point operations per second",
               d_ratio(f, flop), "100%"),
        Metric(f"{group}_flops", desc + " floating point operations per second",
               fl_r, "flops/s"),
        Metric(f"{group}_ops", desc + " operations per second",
               r_s, "ops/s"),
    ])

  return MetricGroup("fpu", [
      MetricGroup("fpu_total", [
          Metric("fpu_total_flops", "Floating point operations per second",
                 flop_r, "flops/s"),
          Metric("fpu_total_flopc", "Floating point operations per cycle",
                 flop_c, "flops/cycle", constraint=nmi_constraint),
      ]),
      MetricGroup("fpu_64", [
          FpuMetrics("fpu_64_single", s_64, 1, "64-bit single"),
          FpuMetrics("fpu_64_double", d_64, 1, "64-bit double"),
      ]),
      MetricGroup("fpu_128", [
          FpuMetrics("fpu_128_single", s_128, 4, "128-bit packed single"),
          FpuMetrics("fpu_128_double", d_128, 2, "128-bit packed double"),
      ]),
      MetricGroup("fpu_256", [
          FpuMetrics("fpu_256_single", s_256, 8, "128-bit packed single"),
          FpuMetrics("fpu_256_double", d_256, 4, "128-bit packed double"),
      ]),
      MetricGroup("fpu_512", [
          FpuMetrics("fpu_512_single", s_512, 16, "128-bit packed single"),
          FpuMetrics("fpu_512_double", d_512, 8, "128-bit packed double"),
      ]),
      Metric("fpu_assists", "FP assists as a percentage of cycles",
             d_ratio(f_assist, cyc), "100%"),
  ])


def IntelIlp() -> MetricGroup:
  tsc = Event("msr/tsc/")
  c0 = Event("msr/mperf/")
  low = tsc - c0
  inst_ret = Event("INST_RETIRED.ANY_P")
  inst_ret_c = [Event(f"{inst_ret.name}/cmask={x}/") for x in range(1, 6)]
  core_cycles = Event("CPU_CLK_UNHALTED.THREAD_P_ANY",
                      "CPU_CLK_UNHALTED.DISTRIBUTED",
                      "cycles")
  ilp = [d_ratio(max(inst_ret_c[x] - inst_ret_c[x + 1], 0), core_cycles) for x in range(0, 4)]
  ilp.append(d_ratio(inst_ret_c[4], core_cycles))
  ilp0 = 1
  for x in ilp:
    ilp0 -= x
  return MetricGroup("ilp", [
      Metric("ilp_idle", "Lower power cycles as a percentage of all cycles",
             d_ratio(low, tsc), "100%"),
      Metric("ilp_inst_ret_0", "Instructions retired in 0 cycles as a percentage of all cycles",
             ilp0, "100%"),
      Metric("ilp_inst_ret_1", "Instructions retired in 1 cycles as a percentage of all cycles",
             ilp[0], "100%"),
      Metric("ilp_inst_ret_2", "Instructions retired in 2 cycles as a percentage of all cycles",
             ilp[1], "100%"),
      Metric("ilp_inst_ret_3", "Instructions retired in 3 cycles as a percentage of all cycles",
             ilp[2], "100%"),
      Metric("ilp_inst_ret_4", "Instructions retired in 4 cycles as a percentage of all cycles",
             ilp[3], "100%"),
      Metric("ilp_inst_ret_5", "Instructions retired in 5 or more cycles as a percentage of all cycles",
             ilp[4], "100%"),
  ])


def IntelL2() -> Optional[MetricGroup]:
  try:
    DC_HIT = Event("L2_RQSTS.DEMAND_DATA_RD_HIT")
  except:
    return None
  try:
    DC_MISS = Event("L2_RQSTS.DEMAND_DATA_RD_MISS")
    l2_dmnd_miss = DC_MISS
    l2_dmnd_rd_all = DC_MISS + DC_HIT
  except:
    DC_ALL = Event("L2_RQSTS.ALL_DEMAND_DATA_RD")
    l2_dmnd_miss = DC_ALL - DC_HIT
    l2_dmnd_rd_all = DC_ALL
  l2_dmnd_mrate = d_ratio(l2_dmnd_miss, interval_sec)
  l2_dmnd_rrate = d_ratio(l2_dmnd_rd_all, interval_sec)

  DC_PFH = None
  DC_PFM = None
  l2_pf_all = None
  l2_pf_mrate = None
  l2_pf_rrate = None
  try:
    DC_PFH = Event("L2_RQSTS.PF_HIT")
    DC_PFM = Event("L2_RQSTS.PF_MISS")
    l2_pf_all = DC_PFH + DC_PFM
    l2_pf_mrate = d_ratio(DC_PFM, interval_sec)
    l2_pf_rrate = d_ratio(l2_pf_all, interval_sec)
  except:
    pass

  DC_RFOH = None
  DC_RFOM = None
  l2_rfo_all = None
  l2_rfo_mrate  = None
  l2_rfo_rrate  = None
  try:
    DC_RFOH = Event("L2_RQSTS.RFO_HIT")
    DC_RFOM = Event("L2_RQSTS.RFO_MISS")
    l2_rfo_all = DC_RFOH + DC_RFOM
    l2_rfo_mrate  = d_ratio(DC_RFOM, interval_sec)
    l2_rfo_rrate  = d_ratio(l2_rfo_all, interval_sec)
  except:
    pass

  DC_CH = None
  try:
    DC_CH = Event("L2_RQSTS.CODE_RD_HIT")
  except:
    pass
  DC_CM = Event("L2_RQSTS.CODE_RD_MISS")
  DC_IN = Event("L2_LINES_IN.ALL")
  DC_OUT_NS = None
  DC_OUT_S = None
  l2_lines_out = None
  l2_out_rate = None
  wbn = None
  isd = None
  try:
    DC_OUT_NS = Event("L2_LINES_OUT.NON_SILENT",
                      "L2_LINES_OUT.DEMAND_DIRTY",
                      "L2_LINES_IN.S")
    DC_OUT_S = Event("L2_LINES_OUT.SILENT",
                     "L2_LINES_OUT.DEMAND_CLEAN",
                     "L2_LINES_IN.I")
    if DC_OUT_S.name == "L2_LINES_OUT.SILENT" and (
        args.model.startswith("skylake") or
        args.model == "cascadelakex"):
      DC_OUT_S.name = "L2_LINES_OUT.SILENT/any/"
    # bring is back to per-CPU
    l2_s  = Select(DC_OUT_S / 2, Literal("#smt_on"), DC_OUT_S)
    l2_ns = DC_OUT_NS
    l2_lines_out = l2_s + l2_ns;
    l2_out_rate = d_ratio(l2_lines_out, interval_sec);
    nlr = max(l2_ns - DC_WB_U - DC_WB_D, 0)
    wbn = d_ratio(nlr, interval_sec)
    isd = d_ratio(l2_s, interval_sec)
  except:
    pass
  DC_OUT_U = None
  l2_pf_useless = None
  l2_useless_rate = None
  try:
    DC_OUT_U = Event("L2_LINES_OUT.USELESS_HWPF")
    l2_pf_useless = DC_OUT_U
    l2_useless_rate = d_ratio(l2_pf_useless, interval_sec)
  except:
    pass
  DC_WB_U = None
  DC_WB_D = None
  wbu = None
  wbd = None
  try:
    DC_WB_U = Event("IDI_MISC.WB_UPGRADE")
    DC_WB_D = Event("IDI_MISC.WB_DOWNGRADE")
    wbu = d_ratio(DC_WB_U, interval_sec)
    wbd = d_ratio(DC_WB_D, interval_sec)
  except:
    pass

  l2_lines_in = DC_IN
  l2_code_all = (DC_CH + DC_CM) if DC_CH else None
  l2_code_rate = d_ratio(l2_code_all, interval_sec) if DC_CH else None
  l2_code_miss_rate = d_ratio(DC_CM, interval_sec)
  l2_in_rate = d_ratio(l2_lines_in, interval_sec)

  return MetricGroup("l2", [
    MetricGroup("l2_totals", [
      Metric("l2_totals_in", "L2 cache total in per second",
             l2_in_rate, "In/s"),
      Metric("l2_totals_out", "L2 cache total out per second",
             l2_out_rate, "Out/s") if l2_out_rate else None,
    ]),
    MetricGroup("l2_rd", [
      Metric("l2_rd_hits", "L2 cache data read hits",
             d_ratio(DC_HIT, l2_dmnd_rd_all), "100%"),
      Metric("l2_rd_hits", "L2 cache data read hits",
             d_ratio(l2_dmnd_miss, l2_dmnd_rd_all), "100%"),
      Metric("l2_rd_requests", "L2 cache data read requests per second",
             l2_dmnd_rrate, "requests/s"),
      Metric("l2_rd_misses", "L2 cache data read misses per second",
             l2_dmnd_mrate, "misses/s"),
    ]),
    MetricGroup("l2_hwpf", [
      Metric("l2_hwpf_hits", "L2 cache hardware prefetcher hits",
             d_ratio(DC_PFH, l2_pf_all), "100%"),
      Metric("l2_hwpf_misses", "L2 cache hardware prefetcher misses",
             d_ratio(DC_PFM, l2_pf_all), "100%"),
      Metric("l2_hwpf_useless", "L2 cache hardware prefetcher useless prefetches per second",
             l2_useless_rate, "100%") if l2_useless_rate else None,
      Metric("l2_hwpf_requests", "L2 cache hardware prefetcher requests per second",
             l2_pf_rrate, "100%"),
      Metric("l2_hwpf_misses", "L2 cache hardware prefetcher misses per second",
             l2_pf_mrate, "100%"),
    ]) if DC_PFH else None,
    MetricGroup("l2_rfo", [
      Metric("l2_rfo_hits", "L2 cache request for ownership (RFO) hits",
             d_ratio(DC_RFOH, l2_rfo_all), "100%"),
      Metric("l2_rfo_misses", "L2 cache request for ownership (RFO) misses",
             d_ratio(DC_RFOM, l2_rfo_all), "100%"),
      Metric("l2_rfo_requests", "L2 cache request for ownership (RFO) requests per second",
             l2_rfo_rrate, "requests/s"),
      Metric("l2_rfo_misses", "L2 cache request for ownership (RFO) misses per second",
             l2_rfo_mrate, "misses/s"),
    ]) if DC_RFOH else None,
    MetricGroup("l2_code", [
      Metric("l2_code_hits", "L2 cache code hits",
             d_ratio(DC_CH, l2_code_all), "100%") if DC_CH else None,
      Metric("l2_code_misses", "L2 cache code misses",
             d_ratio(DC_CM, l2_code_all), "100%") if DC_CH else None,
      Metric("l2_code_requests", "L2 cache code requests per second",
             l2_code_rate, "requests/s") if DC_CH else None,
      Metric("l2_code_misses", "L2 cache code misses per second",
             l2_code_miss_rate, "misses/s"),
    ]),
    MetricGroup("l2_evict", [
      MetricGroup("l2_evict_mef_lines", [
        Metric("l2_evict_mef_lines_l3_hot_lru", "L2 evictions M/E/F lines L3 hot LRU per second",
               wbu, "HotLRU/s") if wbu else None,
        Metric("l2_evict_mef_lines_l3_norm_lru", "L2 evictions M/E/F lines L3 normal LRU per second",
               wbn, "NormLRU/s") if wbn else None,
        Metric("l2_evict_mef_lines_dropped", "L2 evictions M/E/F lines dropped per second",
               wbd, "dropped/s") if wbd else None,
        Metric("l2_evict_is_lines_dropped", "L2 evictions I/S lines dropped per second",
               isd, "dropped/s") if isd else None,
      ]),
    ]),
  ], description = "L2 data cache analysis")


def IntelMlp() -> Optional[Metric]:
  try:
    l1d = Event("L1D_PEND_MISS.PENDING")
    l1dc = Event("L1D_PEND_MISS.PENDING_CYCLES")
  except:
    return None

  l1dc = Select(l1dc / 2, Literal("#smt_on"), l1dc)
  ml = d_ratio(l1d, l1dc)
  return Metric("mlp",
                "Miss level parallelism - number of outstanding load misses per cycle (higher is better)",
                ml, "load_miss_pending/cycle")


def IntelPorts() -> Optional[MetricGroup]:
  pipeline_events = json.load(open(f"{_args.events_path}/x86/{_args.model}/pipeline.json"))

  core_cycles = Event("CPU_CLK_UNHALTED.THREAD_P_ANY",
                      "CPU_CLK_UNHALTED.DISTRIBUTED",
                      "cycles")
  # Number of CPU cycles scaled for SMT.
  smt_cycles = Select(core_cycles / 2, Literal("#smt_on"), core_cycles)

  metrics = []
  for x in pipeline_events:
    if "EventName" in x and re.search("^UOPS_DISPATCHED.PORT", x["EventName"]):
      name = x["EventName"]
      port = re.search(r"(PORT_[0-9].*)", name).group(0).lower()
      if name.endswith("_CORE"):
        cyc = core_cycles
      else:
        cyc = smt_cycles
      metrics.append(Metric(port, f"{port} utilization (higher is better)",
                            d_ratio(Event(name), cyc), "100%"))
  if len(metrics) == 0:
    return None

  return MetricGroup("ports", metrics, "functional unit (port) utilization -- "
                     "fraction of cycles each port is utilized (higher is better)")


def IntelSwpf() -> Optional[MetricGroup]:
  ins = Event("instructions")
  try:
    s_ld = Event("MEM_INST_RETIRED.ALL_LOADS", "MEM_UOPS_RETIRED.ALL_LOADS")
    s_nta = Event("SW_PREFETCH_ACCESS.NTA")
    s_t0 = Event("SW_PREFETCH_ACCESS.T0")
    s_t1 = Event("SW_PREFETCH_ACCESS.T1_T2")
    s_w = Event("SW_PREFETCH_ACCESS.PREFETCHW")
  except:
    return None

  all_sw = s_nta + s_t0 + s_t1 + s_w
  swp_r = d_ratio(all_sw, interval_sec)
  ins_r = d_ratio(ins, all_sw)
  ld_r = d_ratio(s_ld, all_sw)

  return MetricGroup("swpf", [
      MetricGroup("swpf_totals", [
          Metric("swpf_totals_exec", "Software prefetch instructions per second",
                swp_r, "swpf/s"),
          Metric("swpf_totals_insn_per_pf",
                 "Average number of instructions between software prefetches",
                 ins_r, "insn/swpf"),
          Metric("swpf_totals_loads_per_pf",
                 "Average number of loads between software prefetches",
                 ld_r, "loads/swpf"),
      ]),
      MetricGroup("swpf_bkdwn", [
          MetricGroup("swpf_bkdwn_nta", [
              Metric("swpf_bkdwn_nta_per_swpf",
                     "Software prefetch NTA instructions as a percent of all prefetch instructions",
                     d_ratio(s_nta, all_sw), "100%"),
              Metric("swpf_bkdwn_nta_rate",
                     "Software prefetch NTA instructions per second",
                     d_ratio(s_nta, interval_sec), "insn/s"),
          ]),
          MetricGroup("swpf_bkdwn_t0", [
              Metric("swpf_bkdwn_t0_per_swpf",
                     "Software prefetch T0 instructions as a percent of all prefetch instructions",
                     d_ratio(s_t0, all_sw), "100%"),
              Metric("swpf_bkdwn_t0_rate",
                     "Software prefetch T0 instructions per second",
                     d_ratio(s_t0, interval_sec), "insn/s"),
          ]),
          MetricGroup("swpf_bkdwn_t1_t2", [
              Metric("swpf_bkdwn_t1_t2_per_swpf",
                     "Software prefetch T1 or T2 instructions as a percent of all prefetch instructions",
                     d_ratio(s_t1, all_sw), "100%"),
              Metric("swpf_bkdwn_t1_t2_rate",
                     "Software prefetch T1 or T2 instructions per second",
                     d_ratio(s_t1, interval_sec), "insn/s"),
          ]),
          MetricGroup("swpf_bkdwn_w", [
              Metric("swpf_bkdwn_w_per_swpf",
                     "Software prefetch W instructions as a percent of all prefetch instructions",
                     d_ratio(s_w, all_sw), "100%"),
              Metric("swpf_bkdwn_w_rate",
                     "Software prefetch W instructions per second",
                     d_ratio(s_w, interval_sec), "insn/s"),
          ]),
      ]),
  ], description="Software prefetch instruction breakdown")


def IntelLdSt() -> Optional[MetricGroup]:
  if _args.model in [
      "bonnell",
      "nehalemep",
      "nehalemex",
      "westmereep-dp",
      "westmereep-sp",
      "westmereex",
  ]:
    return None
  LDST_LD = Event("MEM_INST_RETIRED.ALL_LOADS", "MEM_UOPS_RETIRED.ALL_LOADS")
  LDST_ST = Event("MEM_INST_RETIRED.ALL_STORES", "MEM_UOPS_RETIRED.ALL_STORES")
  LDST_LDC1 = Event(f"{LDST_LD.name}/cmask=1/")
  LDST_STC1 = Event(f"{LDST_ST.name}/cmask=1/")
  LDST_LDC2 = Event(f"{LDST_LD.name}/cmask=2/")
  LDST_STC2 = Event(f"{LDST_ST.name}/cmask=2/")
  LDST_LDC3 = Event(f"{LDST_LD.name}/cmask=3/")
  LDST_STC3 = Event(f"{LDST_ST.name}/cmask=3/")
  ins = Event("instructions")
  LDST_CYC = Event("CPU_CLK_UNHALTED.THREAD",
                   "CPU_CLK_UNHALTED.CORE_P",
                   "CPU_CLK_UNHALTED.THREAD_P")
  LDST_PRE = None
  try:
    LDST_PRE = Event("LOAD_HIT_PREFETCH.SWPF", "LOAD_HIT_PRE.SW_PF")
  except:
    pass
  LDST_AT = None
  try:
    LDST_AT = Event("MEM_INST_RETIRED.LOCK_LOADS")
  except:
    pass
  cyc  = LDST_CYC

  ld_rate = d_ratio(LDST_LD, interval_sec)
  st_rate = d_ratio(LDST_ST, interval_sec)
  pf_rate = d_ratio(LDST_PRE, interval_sec) if LDST_PRE else None
  at_rate = d_ratio(LDST_AT, interval_sec) if LDST_AT else None

  ldst_ret_constraint = MetricConstraint.GROUPED_EVENTS
  if LDST_LD.name == "MEM_UOPS_RETIRED.ALL_LOADS":
    ldst_ret_constraint = MetricConstraint.NO_GROUP_EVENTS_NMI

  return MetricGroup("ldst", [
      MetricGroup("ldst_total", [
          Metric("ldst_total_loads", "Load/store instructions total loads",
                 ld_rate, "loads"),
          Metric("ldst_total_stores", "Load/store instructions total stores",
                 st_rate, "stores"),
      ]),
      MetricGroup("ldst_prcnt", [
          Metric("ldst_prcnt_loads", "Percent of all instructions that are loads",
                 d_ratio(LDST_LD, ins), "100%"),
          Metric("ldst_prcnt_stores", "Percent of all instructions that are stores",
                 d_ratio(LDST_ST, ins), "100%"),
      ]),
      MetricGroup("ldst_ret_lds", [
          Metric("ldst_ret_lds_1", "Retired loads in 1 cycle",
                 d_ratio(max(LDST_LDC1 - LDST_LDC2, 0), cyc), "100%",
                 constraint = ldst_ret_constraint),
          Metric("ldst_ret_lds_2", "Retired loads in 2 cycles",
                 d_ratio(max(LDST_LDC2 - LDST_LDC3, 0), cyc), "100%",
                 constraint = ldst_ret_constraint),
          Metric("ldst_ret_lds_3", "Retired loads in 3 or more cycles",
                 d_ratio(LDST_LDC3, cyc), "100%"),
      ]),
      MetricGroup("ldst_ret_sts", [
          Metric("ldst_ret_sts_1", "Retired stores in 1 cycle",
                 d_ratio(max(LDST_STC1 - LDST_STC2, 0), cyc), "100%",
                 constraint = ldst_ret_constraint),
          Metric("ldst_ret_sts_2", "Retired stores in 2 cycles",
                 d_ratio(max(LDST_STC2 - LDST_STC3, 0), cyc), "100%",
                 constraint = ldst_ret_constraint),
          Metric("ldst_ret_sts_3", "Retired stores in 3 more cycles",
                 d_ratio(LDST_STC3, cyc), "100%"),
      ]),
      Metric("ldst_ld_hit_swpf", "Load hit software prefetches per second",
             pf_rate, "swpf/s") if pf_rate else None,
      Metric("ldst_atomic_lds", "Atomic loads per second",
             at_rate, "loads/s") if at_rate else None,
  ], description = "Breakdown of load/store instructions")


def main() -> None:
  global _args

  def dir_path(path: str) -> str:
    """Validate path is a directory for argparse."""
    if os.path.isdir(path):
      return path
    raise argparse.ArgumentTypeError(f'\'{path}\' is not a valid directory')

  parser = argparse.ArgumentParser(description="Intel perf json generator")
  parser.add_argument("-metricgroups", help="Generate metricgroups data", action='store_true')
  parser.add_argument("model", help="e.g. skylakex")
  parser.add_argument(
      'events_path',
      type=dir_path,
      help='Root of tree containing architecture directories containing json files'
  )
  _args = parser.parse_args()

  directory = f"{_args.events_path}/x86/{_args.model}/"
  LoadEvents(directory)

  all_metrics = MetricGroup("", [
      Idle(),
      Rapl(),
      Smi(),
      Tsx(),
      IntelBr(),
      IntelCtxSw(),
      IntelFpu(),
      IntelIlp(),
      IntelL2(),
      IntelLdSt(),
      IntelMlp(),
      IntelPorts(),
      IntelSwpf(),
  ])


  if _args.metricgroups:
    print(JsonEncodeMetricGroupDescriptions(all_metrics))
  else:
    print(JsonEncodeMetric(all_metrics))

if __name__ == '__main__':
  main()
