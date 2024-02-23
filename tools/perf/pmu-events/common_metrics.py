# SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
from metric import (d_ratio, Event, Metric, MetricGroup)

def Cycles() -> MetricGroup:
  cyc_k = Event("cycles:kHh")
  cyc_g = Event("cycles:G")
  cyc_u = Event("cycles:uH")
  cyc = cyc_k + cyc_g + cyc_u

  return MetricGroup("cycles", [
      Metric("cycles_total", "Total number of cycles", cyc, "cycles"),
      Metric("cycles_user", "User cycles as a percentage of all cycles",
             d_ratio(cyc_u, cyc), "100%"),
      Metric("cycles_kernel", "Kernel cycles as a percentage of all cycles",
             d_ratio(cyc_k, cyc), "100%"),
      Metric("cycles_guest", "Hypervisor guest cycles as a percentage of all cycles",
             d_ratio(cyc_g, cyc), "100%"),
  ], description = "cycles breakdown per privilege level (users, kernel, guest)")
