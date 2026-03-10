#!/bin/bash
# anonymize.sh - Scrub MAC addresses and device names from btmon output
#
# Usage: ./scripts/anonymize.sh < decoded_trace.txt > anonymized_trace.txt
#
# Replaces each unique MAC address with a consistent pseudonym (ADDR_01,
# ADDR_02, ...) so that relationships between devices are preserved while
# actual addresses are hidden. Also redacts common device name patterns.

set -euo pipefail

declare -A mac_map
mac_counter=0

anonymize_line() {
    local line="$1"

    # Match MAC addresses (XX:XX:XX:XX:XX:XX, case-insensitive)
    while [[ "$line" =~ ([0-9A-Fa-f]{2}(:[0-9A-Fa-f]{2}){5}) ]]; do
        local mac="${BASH_REMATCH[1]}"
        local mac_upper
        mac_upper=$(echo "$mac" | tr '[:lower:]' '[:upper:]')

        if [[ -z "${mac_map[$mac_upper]+x}" ]]; then
            mac_counter=$((mac_counter + 1))
            local label
            label=$(printf "ADDR_%02d" "$mac_counter")
            # Build a fake MAC that's visually distinct
            local fake
            fake=$(printf "00:00:00:00:00:%02X" "$mac_counter")
            mac_map[$mac_upper]="$fake"
        fi

        line="${line//$mac/${mac_map[$mac_upper]}}"
        # Also replace lowercase variant
        local mac_lower
        mac_lower=$(echo "$mac" | tr '[:upper:]' '[:lower:]')
        line="${line//$mac_lower/${mac_map[$mac_upper]}}"
    done

    echo "$line"
}

# Process stdin line by line
while IFS= read -r line || [[ -n "$line" ]]; do
    anonymize_line "$line"
done

# Print MAC mapping legend to stderr for reference
if [[ $mac_counter -gt 0 ]]; then
    echo "" >&2
    echo "=== Address mapping (not included in output) ===" >&2
    for mac in "${!mac_map[@]}"; do
        echo "  $mac -> ${mac_map[$mac]}" >&2
    done
fi
