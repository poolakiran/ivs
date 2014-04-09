#!/usr/bin/python
import os
import sys
script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(1, os.path.join(script_dir, "..", "submodules", "loxigen-artifacts", "pyloxi"))

import loxi.of13 as ofp
import time
import subprocess
import logging

from cxn import OFConnection
import argparse

parser = argparse.ArgumentParser(description='L2 upcall throughput benchmark')

parser.add_argument('--host', '-H', type=str, default="127.0.0.1", help="Switch IP/Hostname to connect to")
parser.add_argument('--port', '-p', type=int, default=6634, help="Switch port to connect to")

args = parser.parse_args()

logging.basicConfig(
    level=logging.WARN,
    format="%(asctime)s.%(msecs)03d: %(levelname)-8s: %(message)s",
    datefmt="%H:%M:%S")

cxn = OFConnection(args.host, args.port, ofp)

tx_netdev = "veth1"
tx_port = 1
rx_netdev = "veth3"
rx_port = 2

msgs = [
    ofp.message.flow_delete(
        table_id=ofp.OFPTT_ALL,
        buffer_id=ofp.OFP_NO_BUFFER,
        out_port=ofp.OFPP_ANY,
        out_group=ofp.OFPG_ANY),
    ofp.message.group_delete(
        group_id=ofp.OFPG_ALL),
]

for msg in msgs:
    cxn.sendmsg(msg)
cxn.transact(ofp.message.barrier_request())

msgs = [
    # LAG
    ofp.message.group_add(
        group_type=ofp.OFPGT_SELECT,
        group_id=1,
        buckets=[
            ofp.bucket(
                weight=1,
                watch_port=ofp.OFPP_ANY, watch_group=ofp.OFPG_ANY,
                actions=[ofp.action.output(tx_port)])]),
    ofp.message.group_add(
        group_type=ofp.OFPGT_SELECT,
        group_id=2,
        buckets=[
            ofp.bucket(
                weight=1,
                watch_port=ofp.OFPP_ANY, watch_group=ofp.OFPG_ANY,
                actions=[ofp.action.output(rx_port)])]),

    # Port
    ofp.message.flow_add(
        table_id=2,
        match=ofp.match([ofp.oxm.in_port(tx_port)]),
        instructions=[
            ofp.instruction.apply_actions([
                ofp.action.set_field(ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|1000)),
                ofp.action.set_field(ofp.oxm.bsn_lag_id(1)),
            ]),
        ],
        buffer_id=ofp.OFP_NO_BUFFER),
    ofp.message.flow_add(
        table_id=2,
        match=ofp.match([ofp.oxm.in_port(rx_port)]),
        instructions=[
            ofp.instruction.apply_actions([
                ofp.action.set_field(ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|1000)),
                ofp.action.set_field(ofp.oxm.bsn_lag_id(2)),
            ]),
        ],
        buffer_id=ofp.OFP_NO_BUFFER),

    # VLAN
    ofp.message.flow_add(
        table_id=1,
        match=ofp.match([
            ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|1000)]),
        instructions=[
            ofp.instruction.apply_actions([
                ofp.action.pop_vlan(),
                ofp.action.output(port=tx_port, max_len=ofp.OFPCML_NO_BUFFER),
                ofp.action.output(port=rx_port, max_len=ofp.OFPCML_NO_BUFFER),
            ])],
        buffer_id=ofp.OFP_NO_BUFFER),

    # L2
    ofp.message.flow_add(
        table_id=0,
        match=ofp.match([
            ofp.oxm.eth_dst([0, 0, 0, 0, 0, 1]),
            ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|1000)]),
        instructions=[
            ofp.instruction.apply_actions(
                actions=[ofp.action.group(1)])],
        buffer_id=ofp.OFP_NO_BUFFER),
    ofp.message.flow_add(
        table_id=0,
        match=ofp.match([
            ofp.oxm.eth_dst([0, 0, 0, 0, 0, 2]),
            ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|1000)]),
        instructions=[
            ofp.instruction.apply_actions(
                actions=[ofp.action.group(2)])],
        buffer_id=ofp.OFP_NO_BUFFER),
]

for msg in msgs:
    cxn.sendmsg(msg)
cxn.transact(ofp.message.barrier_request())

TRAFGEN_CFG = """
{
    /* MAC Destination */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x02
    /* MAC Source */
    0x00, 0x00, 0x00, 0x00, 0x00, 0x01
    /* IPv4 Protocol */
    c16(0x0800),
    /* IPv4 Version, IHL, TOS */
    0b01000101, 0,
    /* IPv4 Total Len */
    c16(59),
    /* IPv4 Ident */
    drnd(2),
    /* IPv4 Flags, Frag Off */
    0b01000000, 0,
    /* IPv4 TTL */
    64,
    /* Proto TCP */
    0x06,
    /* IPv4 Checksum (IP header from, to) */
    csumip(14, 33),
    /* Source IP */
    drnd(4),
    /* Dest IP */
    drnd(4),
    /* TCP Source Port */
    drnd(2),
    /* TCP Dest Port */
    c16(80),
    /* TCP Sequence Number */
    drnd(4),
    /* TCP Ackn. Number */
    c32(0),
    /* TCP Header length + TCP SYN/ECN Flag */
    c16((8 << 12) | (1 << 1) | (1 << 6))
    /* Window Size */
    c16(16),
    /* TCP Checksum (offset IP, offset TCP) */
    csumtcp(14, 34),
    /* TCP Options */
    0x00, 0x00, 0x01, 0x01, 0x08, 0x0a, 0x06,
    0x91, 0x68, 0x7d, 0x06, 0x91, 0x68, 0x6f,
    /* Data blob */
    "gotcha!",
}
"""

tx_packets = 5 * 1000 * 1000

input_filename = "trafgen.cfg"
with open(input_filename, "w") as input_file:
    input_file.write(TRAFGEN_CFG)

def get_rx_packets():
    with open("/proc/net/dev") as f:
        for line in f:
            cols = line.split()
            if cols[0] == rx_netdev + ':':
                return int(cols[2])
    assert False

start_time = time.time()
before = get_rx_packets()

subprocess.check_call(
    ["sudo", "trafgen", "-i", input_filename, "-o", tx_netdev, "-n", str(tx_packets), "-P1"],
    stdout=open("/dev/null"))

after = get_rx_packets()
end_time = time.time()

rx_packets = after - before
elapsed = end_time - start_time
print "Received %d/%d (%.1f%%) packets in %.1fs (%.0f pkt/s)" % (
    rx_packets, tx_packets, 100*float(rx_packets)/tx_packets, elapsed, float(rx_packets)/elapsed)
