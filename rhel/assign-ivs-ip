#!/bin/bash

expected_count=$(grep -o -w "internal-port" /etc/sysconfig/ivs | wc -w)
if [ $expected_count == 0 ]; then
    echo "No internal port is configured for ivs"
    exit 0
fi

actual_count=$(ivs-ctl show | grep "(internal)" | grep -v "inband" | grep -v "ivs" | awk '{print $2}' | wc -l)
if [ $actual_count -lt $expected_count ]; then
    echo "wait 1 second for ivs to bring up internal ports"
    sleep 1
fi

intfs=$(ivs-ctl show | grep "(internal)" | grep -v "inband" | grep -v "ivs" | awk '{print $2}')
for intf in $intfs; do
    ifup $intf;
done
