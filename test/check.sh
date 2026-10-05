#!/bin/sh
# SPDX-License-Identifier: GPL-2.0-or-later
# Dissect a capture with bcmevent.lua and fail on any Lua error, exception,
# or 0x886c frame the dissector did not claim.
#   test/check.sh [capture]                default: test/sample.pcap
#   TSHARK=/path/to/tshark test/check.sh   run another Wireshark build
set -eu
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
cap=${1:-$here/sample.pcap}
tshark=${TSHARK:-tshark}
[ "$(id -u)" -ne 0 ] || { echo "FAIL: tshark does not run Lua scripts as root"; exit 2; }

# Empty config, home and plugin folder, so an installed copy of the plugin
# cannot interfere.
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
trap 'exit 2' HUP INT TERM
export WIRESHARK_CONFIG_DIR="$tmp" HOME="$tmp" WIRESHARK_PLUGIN_DIR="$tmp"
ts() { "$tshark" -n -X "lua_script:$here/../bcmevent.lua" -r "$cap" "$@"; }
# -V builds the whole tree. Without it Wireshark skips items no filter needs,
# and an error raised while building one never happens.
count() { ts -V -Y "$1" > "$tmp/out" || exit 2; grep -c '^Frame [0-9]*:' "$tmp/out" || true; }
frames() { ts -V -Y "$1" | grep -E '^Frame [0-9]+:|Lua Error:|Exception occurred' | cut -c 1-160; }

# Load errors reach stderr. Runtime Lua errors only show up as _ws.lua.error,
# and exceptions as _ws.malformed.expert. Frames the dissector flags itself
# (bcmevent.truncated, bcmevent.invalid) are counted, not failed.
is886c='(eth.type == 0x886c || vlan.etype == 0x886c || sll.etype == 0x886c)'
bad="($is886c || bcmevent) && (_ws.lua.error || _ws.malformed.expert)"
flag='(bcmevent.truncated || bcmevent.invalid)'
err=$(ts -V 2>&1 >/dev/null || true)
total=$(count "$is886c")
claimed=$(count "$is886c && bcmevent")
flagged=$(count "$flag")
errors=$(count "$bad")

"$tshark" -v | head -n 1
echo "0x886c frames: $total  claimed: $claimed  flagged: $flagged  errors: $errors"

fail=0
[ -z "$err" ] || { echo "FAIL: tshark stderr:"; echo "$err"; fail=1; }
[ "$total" -gt 0 ] || { echo "FAIL: no 0x886c frames in $cap"; fail=1; }
[ "$claimed" -eq "$total" ] || {
    echo "FAIL: unclaimed 0x886c frames:"; frames "$is886c && !bcmevent"; fail=1; }
[ "$errors" -eq 0 ] || { echo "FAIL: errors:"; frames "$bad"; fail=1; }
# In test/sample.pcap exactly the frames sent from 02:00:00:00:00:0f must be flagged.
if [ $# -eq 0 ]; then
    mark='eth.src == 02:00:00:00:00:0f'
    [ "$(count "$mark && !$flag")" -eq 0 ] || { echo "FAIL: not flagged:"; frames "$mark && !$flag"; fail=1; }
    [ "$(count "!($mark) && $flag")" -eq 0 ] || { echo "FAIL: flagged:"; frames "!($mark) && $flag"; fail=1; }
fi
[ "$fail" -eq 0 ] && echo PASS
exit "$fail"
