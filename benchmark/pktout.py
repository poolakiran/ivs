#!/usr/bin/python
import os
import sys
script_dir = os.path.dirname(os.path.realpath(__file__))
sys.path.insert(1, os.path.join(script_dir, "..", "submodules", "loxigen-artifacts", "pyloxi"))

import loxi.of13 as ofp
import time
import logging
import socket
import select

from cxn import OFConnection
import argparse

parser = argparse.ArgumentParser(description='Packet-out benchmark')

parser.add_argument('--host', '-H', type=str, default="127.0.0.1", help="Switch IP/Hostname to connect to")
parser.add_argument('--port', '-p', type=int, default=6634, help="Switch port to connect to")

args = parser.parse_args()

logging.basicConfig(
    level=logging.WARN,
    format="%(asctime)s.%(msecs)03d: %(levelname)-8s: %(message)s",
    datefmt="%H:%M:%S")

PKT = [
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    0x88, 0x09,
]
PKT = ''.join(chr(x) for x in PKT)

cxn = OFConnection(args.host, args.port, ofp)

cxn.sock.setblocking(1)

duration = 10
chunk_size = 400

tx_netdev = "veth0"
tx_port = 1

request_buf = ofp.message.packet_out(
    xid=0,
    buffer_id=ofp.OFP_NO_BUFFER,
    in_port=ofp.OFPP_CONTROLLER,
    actions=[ofp.action.output(tx_port)],
    data=PKT
).pack()
request_chunk = request_buf * chunk_size

def get_tx_packets():
    with open("/proc/net/dev") as f:
        for line in f:
            cols = line.split()
            if cols[0] == tx_netdev + ':':
                return int(cols[10])
    assert False

start_time = time.time()
before = get_tx_packets()

while time.time() - start_time < duration:
    cxn.sendraw(request_chunk)

after = get_tx_packets()
elapsed = time.time() - start_time

count = after - before

print "%d pktout messages in %f.1s (%.0f pktout/s)" % (count, elapsed, count/elapsed)
