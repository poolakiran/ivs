#!/bin/bash -eu
################################################################
#
#        Copyright 2013, Big Switch Networks, Inc.
#
# Licensed under the Eclipse Public License, Version 1.0 (the
# "License"); you may not use this file except in compliance
# with the License. You may obtain a copy of the License at
#
#        http://www.eclipse.org/legal/epl-v10.html
#
# Unless required by applicable law or agreed to in writing,
# software distributed under the License is distributed on an
# "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
# either express or implied. See the License for the specific
# language governing permissions and limitations under the
# License.
#
################################################################

N=8
for I in `seq 0 $(($N-1))`; do
    A="veth$(($I*2))"
    B="veth$(($I*2+1))"
    if ! ip link show $A &> /dev/null; then
        ip link add name $A type veth peer name $B
        sysctl net.ipv6.conf.$A.disable_ipv6=1
        sysctl net.ipv6.conf.$B.disable_ipv6=1
        ip link set dev $A up
        ip link set dev $B up
    fi
done
