#!/usr/bin/python
import os
import sys
script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(1, os.path.join(script_dir, "..", "submodules", "loxigen-artifacts", "pyloxi"))

import loxi.of13 as ofp
import time
import logging

from cxn import OFConnection
import argparse

parser = argparse.ArgumentParser(description='Flow-add benchmark')

parser.add_argument('--host', '-H', type=str, default="127.0.0.1", help="Switch IP/Hostname to connect to")
parser.add_argument('--port', '-p', type=int, default=6634, help="Switch port to connect to")

args = parser.parse_args()

logging.basicConfig(
    level=logging.WARN,
    format="%(asctime)s.%(msecs)03d: %(levelname)-8s: %(message)s",
    datefmt="%H:%M:%S")

cxn = OFConnection(args.host, args.port, ofp)
cxn.sock.setblocking(1)

flowmods = []
num_flows = 100000
count = 0
duration = 10

logging.debug("Generating flow-mods")

for i in xrange(0, num_flows):
    flowmods.append(ofp.message.flow_add(
        xid=0,
        table_id=0,
        match=ofp.match([
            ofp.oxm.eth_dst([0, 0, 0, (i >> 16) & 0xff, (i >> 8) & 0xff, i & 0xff]),
            ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|1000)]),
        instructions=[
            ofp.instruction.apply_actions(
                actions=[ofp.action.group(1)])],
        buffer_id=ofp.OFP_NO_BUFFER).pack())
flowmod_buf = ''.join(flowmods)

def delete_all_flows():
    cxn.sendmsg(ofp.message.flow_delete(
	table_id=ofp.OFPTT_ALL,
	buffer_id=ofp.OFP_NO_BUFFER,
	out_port=ofp.OFPP_ANY,
	out_group=ofp.OFPG_ANY)),

    cxn.transact(ofp.message.barrier_request())

delete_all_flows()

logging.debug("Sending flow-mods")

total_elapsed = 0
initial_time = time.time()

while time.time() - initial_time < duration:
    start_time = time.time()
    cxn.sendraw(flowmod_buf)
    count += num_flows
    cxn.transact(ofp.message.barrier_request())
    total_elapsed += time.time() - start_time
    delete_all_flows()

print "%d flowmods in %f.1s (%.0f flowmod/s)" % (count, total_elapsed, count/total_elapsed)
