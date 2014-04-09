# Copyright (c) 2013  BigSwitch Networks

import loxi
import loxi.of10 as ofp10
import loxi.of13 as ofp13
import socket
import select
import struct
import errno
import logging


class OFConnection(object):
    timeout = 10
    next_xid = 1

    def __init__(self, host, port, ofp):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

        self.sock.setblocking(0)
        rv = self.sock.connect_ex((host, port))
        if rv not in [0, errno.EISCONN]:
            read_ready, write_ready, err = \
                select.select([self.sock], [], [self.sock], self.timeout)
            if not read_ready:
                raise RuntimeError('Timeout connecting to openflow agent')
            if err:
                raise RuntimeError('Error connecting to openflow agent')
            rv = self.sock.connect_ex((host, port))
            if rv not in [0, errno.EISCONN]:
                raise RuntimeError('%s connecting to openflow agent' %
                                        errno.errorcode[rv])

        self.sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, True)
        self.ofp = ofp
        self.sendmsg(self.ofp.message.hello())
        hello = self.recvmsg()
        assert(hello.type == self.ofp.OFPT_HELLO)
        if hello.version < self.ofp.OFP_VERSION:
            logging.warn("Expected HELLO version >= %d, received version %d", self.ofp.OFP_VERSION, hello.version)

    def __enter__(self):
        return self

    def __exit__(self, exctype, excval, exctrace):
        self.close()
        return False

    def close(self):
        self.sock.close()

    def sendraw(self, data):
        if self.sock.sendall(data) is not None:
            raise RuntimeError('Failed to send message to openflow agent')

    def sendmsg(self, msg):
        msg.xid = self._gen_xid()
        self.sendraw(msg.pack())
        logging.debug("Sent %s", msg.show())

    def recvraw(self, timeout=None):
        _timeout = timeout or self.timeout
        buf = self._read_exactly(4, timeout=_timeout)
        version, _, msg_len = struct.unpack_from("!BBH", buf)
        buf += self._read_exactly(msg_len - 4, timeout=_timeout)
        return version, buf

    def recvmsg(self, timeout=None):
        version, buf = self.recvraw(timeout=timeout)
        msg = loxi.protocol(version).message.parse_message(buf)
        logging.debug("Received %s", msg.show())
        return msg

    def request_stats_generator(self, request):
        self.sendmsg(request)
        while True:
            reply = self.recvmsg()
            for entry in reply.entries:
                yield entry
            if reply.flags & self.ofp.const.OFPSF_REPLY_MORE == 0:
                break

    def _read_exactly(self, n, timeout=None):
        _timeout = timeout or self.timeout
        bufs = []
        while n > 0:
            read_ready, write_ready, err = \
                select.select([self.sock], [], [self.sock], _timeout)
            if not read_ready:
                raise RuntimeError('Timeout reading for openflow agent')
            if err:
                raise RuntimeError('Error reading from openflow agent')
            b = self.sock.recv(n)
            if len(b) == 0:
                raise RuntimeError('Lost connection to openflow agent')
            n -= len(b)
            bufs.append(b)
        return ''.join(bufs)

    def _gen_xid(self):
        v = self.next_xid
        self.next_xid = self.next_xid + 1
        return v

    def transact(self, msg):
        self.sendmsg(msg)
        reply = None
        while not reply:
            reply = self.recvmsg()
            if reply.xid != msg.xid:
                logging.info("Discarding %s message", str(type(msg)))
                reply = None
        return reply
