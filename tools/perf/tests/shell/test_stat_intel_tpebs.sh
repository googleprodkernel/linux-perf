#!/bin/bash
# test Intel TPEBS counting mode (exclusive)
# SPDX-License-Identifier: GPL-2.0

set -e

ParanoidAndNotRoot() {
  [ "$(id -u)" != 0 ] && [ "$(cat /proc/sys/kernel/perf_event_paranoid)" -gt $1 ]
}

if ! grep -q GenuineIntel /proc/cpuinfo
then
  echo "Skipping non-Intel"
  exit 2
fi

if ParanoidAndNotRoot 0
then
  echo "Skipping paranoid >0 and not root"
  exit 2
fi

cleanup() {
  trap - EXIT TERM INT
}

trap_cleanup() {
  echo "Unexpected signal in ${FUNCNAME[1]}"
  cleanup
  exit 1
}
trap trap_cleanup EXIT TERM INT

# Use this event for testing because it should exist in all platforms
event=cache-misses:R

# Hybrid platforms output like "cpu_atom/cache-misses/R", rather than as above
alt_name=/cache-misses/R

# Without this cmd option, default value or zero is returned
#echo "Testing without --record-tpebs"
#result=$(perf stat -e "$event" true 2>&1)
#[[ "$result" =~ $event || "$result" =~ $alt_name ]] || exit 1

test_with_record_tpebs() {
  echo "Testing with --record-tpebs"
  result=$(perf stat -e "$event" --record-tpebs -a sleep 0.01 2>&1)

  # Expected output:
  # $ perf stat --record-tpebs -e cache-misses:R -a sleep 0.01
  # Events enabled
  # [ perf record: Woken up 2 times to write data ]
  # [ perf record: Captured and wrote 0.056 MB - ]
  #
  #  Performance counter stats for 'system wide':
  #
  #                  0      cache-misses:R
  #
  #        0.013963299 seconds time elapsed
  if [[ ! "$result" =~ "perf record" ]]
  then
    echo "Testing with --record-tpebs [Failed missing perf record]"
    echo "$result"
    exit 1
  fi
  if [[ ! "$result" =~ $event && ! "$result" =~ $alt_name ]]
  then
    echo "Testing with --record-tpebs [Failed missing event name]"
    echo "$result"
    exit 1
  fi
  echo "Testing with --record-tpebs [Success]"
}

test_with_record_tpebs
cleanup
exit 0
