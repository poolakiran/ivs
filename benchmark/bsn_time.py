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

parser = argparse.ArgumentParser(description='bsn_time benchmark')

parser.add_argument('--host', '-H', type=str, default="127.0.0.1", help="Switch IP/Hostname to connect to")
parser.add_argument('--port', '-p', type=int, default=6634, help="Switch port to connect to")

args = parser.parse_args()

logging.basicConfig(
    level=logging.WARN,
    format="%(asctime)s.%(msecs)03d: %(levelname)-8s: %(message)s",
    datefmt="%H:%M:%S")

cxn = OFConnection(args.host, args.port, ofp)

duration = 10
chunk_size = 2000
preload_chunks = 13
sleep_time = 0.020
count = 0

request_buf = ofp.message.bsn_time_request(xid=0).pack()
request_chunk = request_buf * chunk_size
reply_buf = ofp.message.bsn_time_reply(xid=0).pack()
reply_chunk = reply_buf * chunk_size

recv_buf = bytearray("\0" * len(reply_chunk))
recv_buf_len = len(recv_buf)

def send_chunk():
    cxn.sendraw(request_chunk)

def recv_chunk():
    global count
    n = 0
    while n < recv_buf_len:
        try:
            n += cxn.sock.recv_into(recv_buf[n:])
        except socket.error:
            time.sleep(sleep_time)
    count += chunk_size

start_time = time.time()

for i in xrange(0, preload_chunks):
    send_chunk()

while time.time() - start_time < duration:
    send_chunk()
    recv_chunk()

for i in xrange(0, preload_chunks):
    recv_chunk()

elapsed = time.time() - start_time

print "%d bsn_time messages in %f.1s (%.0f bsn_time/s)" % (count, elapsed, count/elapsed)
