#!/usr/bin/env python3
# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
from metric import (d_ratio, has_event, max, Event, JsonEncodeMetric,
                    JsonEncodeMetricGroupDescriptions, LoadEvents, Metric,
                    MetricGroup, Select)
import argparse
import json
import math
import os

# Global command line arguments.
_args = None

interval_sec = Event("duration_time")

def Idle() -> Metric:
  cyc = Event("msr/mperf/")
  tsc = Event("msr/tsc/")
  low = max(tsc - cyc, 0)
  return Metric(
      "lpm_idle",
      "Percentage of total wallclock cycles where CPUs are in low power state (C1 or deeper sleep state)",
      d_ratio(low, tsc), "100%")


def Rapl() -> MetricGroup:
  """Processor socket power consumption estimate.

  Use events from the running average power limit (RAPL) driver.
  """
  # Watts = joules/second
  # Currently only energy-pkg is supported by AMD:
  # https://lore.kernel.org/lkml/20220105185659.643355-1-eranian@google.com/
  pkg = Event("power/energy\\-pkg/")
  cond_pkg = Select(pkg, has_event(pkg), math.nan)
  scale = 2.3283064365386962890625e-10
  metrics = [
      Metric("lpm_cpu_power_pkg", "",
             d_ratio(cond_pkg * scale, interval_sec), "Watts"),
  ]

  return MetricGroup("lpm_cpu_power", metrics,
                     description="Processor socket power consumption estimates")


def main() -> None:
  global _args

  def dir_path(path: str) -> str:
    """Validate path is a directory for argparse."""
    if os.path.isdir(path):
      return path
    raise argparse.ArgumentTypeError(f'\'{path}\' is not a valid directory')

  parser = argparse.ArgumentParser(description="AMD perf json generator")
  parser.add_argument("-metricgroups", help="Generate metricgroups data", action='store_true')
  parser.add_argument("model", help="e.g. amdzen[123]")
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
  ])

  if _args.metricgroups:
    print(JsonEncodeMetricGroupDescriptions(all_metrics))
  else:
    print(JsonEncodeMetric(all_metrics))

if __name__ == '__main__':
  main()
