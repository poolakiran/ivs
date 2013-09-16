# Copyright (c) 2012, 2013 Big Switch Networks, Inc.
"""
Experimental pipeline testcases
"""

import logging
from collections import namedtuple

from oftest import config
import oftest.base_tests as base_tests
import ofp

from oftest.testutils import *
from oftest.parse import parse_mac

Host = namedtuple("Host", ["vlan", "mac", "port", "tag"])

BSN_PACKET_IN_REASON_NEW_HOST = 128
BSN_PACKET_IN_REASON_STATION_MOVE = 129
BSN_PACKET_IN_REASON_BAD_VLAN = 130
BSN_PACKET_IN_REASON_DESTINATION_LOOKUP_FAILURE = 131

TABLE_ID_L2 = 0
TABLE_ID_VLAN = 1
TABLE_ID_PORT = 2
TABLE_ID_VLAN_XLATE = 3
TABLE_ID_EGR_VLAN_XLATE = 4

class BasePipelineTest(base_tests.SimpleDataPlane):
    def setUp(self):
        """
        Setup switch
        """
        base_tests.SimpleDataPlane.setUp(self)
        self.ports = openflow_ports(4)
        delete_all_flows(self.controller)
        self.dataplane.flush()

    def insert_host_entries(self, hosts):
        """
        Insert simple entries in the l2, vlan, and port tables

        Few tests should need different flows in these tables. In case one does,
        insert all the flows manually rather than modifying this function. Or,
        insert new flows to replace some of those inserted by this function.
        """
        # Populate l2 table
        for host in hosts:
            self.insert_l2_entry(host.vlan, host.mac, host.port)

        # Populate VLAN table
        vlan_membership = {}
        for host in hosts:
            if host.vlan not in vlan_membership:
                vlan_membership[host.vlan] = []
            vlan_membership[host.vlan].append(host.port)

        for vlan, ports in vlan_membership.items():
            untagged_ports = [host.port for host in hosts if host.vlan == vlan and host.tag == None]
            tagged_ports = list(set(ports) - set(untagged_ports))
            self.insert_vlan_entry(vlan, sorted(tagged_ports), sorted(untagged_ports))

        # Populate port table
        for port in self.ports:
            default_vlans = [host.vlan for host in hosts if host.port == port and host.tag == None]
            if len(default_vlans) == 0:
                self.insert_port_entry(port, None)
            elif len(default_vlans) == 1:
                self.insert_port_entry(port, default_vlans[0])
            else:
                # Multiple potential default VLANs. The test needs to insert
                # this entry itself.
                pass

        # Populate vlan_xlate and egr_vlan_xlate table
        for host in hosts:
            if host.tag == None or host.tag == vlan:
                continue
            self.insert_vlan_xlate_entry(host.port, host.tag, host.vlan)
            self.insert_egr_vlan_xlate_entry(host.port, host.vlan, host.tag)

    def insert_l2_entry(self, vlan, mac, port):
        logging.info("Inserting l2 entry vlan=%d mac=%s -> port=%d", vlan, mac, port)
        request = ofp.message.flow_add(
                table_id=TABLE_ID_L2,
                match=ofp.match([
                    ofp.oxm.eth_dst(parse_mac(mac)),
                    ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|vlan)]),
                instructions=[
                    ofp.instruction.apply_actions(
                        actions=[
                            ofp.action.output(
                                port=port,
                                max_len=ofp.OFPCML_NO_BUFFER)])],
                buffer_id=ofp.OFP_NO_BUFFER)
        self.controller.message_send(request)

    def insert_vlan_entry(self, vlan, tagged_ports, untagged_ports):
        logging.info("Inserting vlan entry vlan=%d -> tagged_ports=%r, untagged_ports=%r", vlan, tagged_ports, untagged_ports)

        actions = []
        for port in tagged_ports:
            actions.append(ofp.action.output(port=port, max_len=ofp.OFPCML_NO_BUFFER))
        actions.append(ofp.action.pop_vlan())
        for port in untagged_ports:
            actions.append(ofp.action.output(port=port, max_len=ofp.OFPCML_NO_BUFFER))

        request = ofp.message.flow_add(
                table_id=TABLE_ID_VLAN,
                match=ofp.match([
                    ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|vlan)]),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER)
        self.controller.message_send(request)

    def insert_port_entry(self, port, default_vlan_vid):
        logging.info("Inserting port entry port=%d -> default_vlan_vid=%r", port, default_vlan_vid)
        actions = []
        if default_vlan_vid != None:
            actions.append(ofp.action.set_field(ofp.oxm.vlan_vid(default_vlan_vid)))
        request = ofp.message.flow_add(
                table_id=TABLE_ID_PORT,
                match=ofp.match([
                    ofp.oxm.in_port(port)]),
                instructions=[
                    ofp.instruction.apply_actions(actions)],
                buffer_id=ofp.OFP_NO_BUFFER)
        self.controller.message_send(request)

    def insert_vlan_xlate_entry(self, port, vlan, new_vlan):
        logging.info("Inserting vlan_xlate entry port=%d, vlan=%d -> new_vlan=%d", port, vlan, new_vlan)
        request = ofp.message.flow_add(
                table_id=TABLE_ID_VLAN_XLATE,
                match=ofp.match([
                    ofp.oxm.in_port(port),
                    ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|vlan)]),
                instructions=[
                    ofp.instruction.apply_actions([
                        ofp.action.set_field(ofp.oxm.vlan_vid(new_vlan))])],
                buffer_id=ofp.OFP_NO_BUFFER)
        self.controller.message_send(request)

    def insert_egr_vlan_xlate_entry(self, port, vlan, new_vlan):
        logging.info("Inserting egr_vlan_xlate entry port=%d, vlan=%d -> new_vlan=%d", port, vlan, new_vlan)
        request = ofp.message.flow_add(
                table_id=TABLE_ID_EGR_VLAN_XLATE,
                match=ofp.match([
                    ofp.oxm.in_port(port),
                    ofp.oxm.vlan_vid(ofp.OFPVID_PRESENT|vlan)]),
                instructions=[
                    ofp.instruction.apply_actions([
                        ofp.action.set_field(ofp.oxm.vlan_vid(new_vlan))])],
                buffer_id=ofp.OFP_NO_BUFFER)
        self.controller.message_send(request)

    def check_rx(self, ofport, pkt):
        """
        Check that an expected packet is received
        """
        logging.debug("Checking for pkt on port %r", ofport)
        (rcv_port, rcv_pkt, pkt_time) = self.dataplane.poll(port_number=ofport, exp_pkt=pkt)
        self.assertTrue(rcv_pkt != None, "Did not receive pkt on %r" % ofport)

    def check_no_rx(self):
        """
        Check that no unexpected packets are received
        """
        logging.debug("Checking for unexpected packets on all ports")
        (rcv_port, rcv_pkt, pkt_time) = self.dataplane.poll(timeout=0.01)
        if rcv_pkt != None:
            logging.debug("Received unexpected packet on port %r: %s", rcv_port, format_packet(rcv_pkt))
        self.assertTrue(rcv_pkt == None, "Unexpected pkt on port %r" % rcv_port)

class Forwarding(BasePipelineTest):
    """
    Send packets between hosts and verify VLAN isolation
    """
    def runTest(self):
        hosts = [
            Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=1),
            Host(vlan=1, mac="00:00:00:00:01:02", port=self.ports[1], tag=1),
            Host(vlan=2, mac="00:00:00:00:02:03", port=self.ports[2], tag=2),
            Host(vlan=2, mac="00:00:00:00:02:04", port=self.ports[3], tag=2),
        ]

        self.insert_host_entries(hosts)
        do_barrier(self.controller)

        for hostA in hosts:
            for hostB in hosts:
                if hostA is hostB:
                    continue

                expect_success = hostA.vlan == hostB.vlan

                logging.info("Sending from %d/%s to %d/%s. Expecting %s.",
                             hostA.vlan, hostA.mac, hostB.vlan, hostB.mac,
                             expect_success and "success" or "failure")

                pkt = str(simple_tcp_packet(eth_src=hostA.mac,
                                            eth_dst=hostB.mac,
                                            dl_vlan_enable=True, vlan_vid=hostA.vlan))
                self.dataplane.send(hostA.port, pkt)
                if expect_success:
                    self.check_rx(hostB.port, pkt)
                    self.check_no_rx()
                else:
                    self.check_no_rx()
                    verify_packet_in(self, pkt, hostA.port, BSN_PACKET_IN_REASON_DESTINATION_LOOKUP_FAILURE)

class Broadcast(BasePipelineTest):
    """
    Send packets to the broadcast address and verify VLAN isolation
    """
    def runTest(self):
        host1 = Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=1)
        host2 = Host(vlan=1, mac="00:00:00:00:01:02", port=self.ports[1], tag=1)
        host3 = Host(vlan=2, mac="00:00:00:00:02:03", port=self.ports[2], tag=2)

        self.insert_host_entries([host1, host2, host3])
        do_barrier(self.controller)

        pkt = str(simple_tcp_packet(eth_src=host1.mac,
                                    eth_dst="ff:ff:ff:ff:ff:ff",
                                    dl_vlan_enable=True, vlan_vid=host1.vlan))
        self.dataplane.send(host1.port, pkt)
        self.check_rx(host2.port, pkt)
        self.check_no_rx()

class NewHost(BasePipelineTest):
    """
    Verify packets from an unknown source are dropped
    """
    def runTest(self):
        host1 = Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=1)
        host2 = Host(vlan=1, mac="00:00:00:00:01:02", port=self.ports[1], tag=2)

        self.insert_host_entries([host1, host2])
        do_barrier(self.controller)

        pkt = str(simple_tcp_packet(eth_src="00:00:00:00:01:03",
                                    eth_dst=host2.mac,
                                    dl_vlan_enable=True, vlan_vid=host1.vlan))
        self.dataplane.send(host1.port, pkt)
        self.check_no_rx()
        verify_packet_in(self, pkt, host1.port, BSN_PACKET_IN_REASON_NEW_HOST)

class StationMove(BasePipelineTest):
    """
    Verify packets from a port not associated with the host are dropped
    """
    def runTest(self):
        host1 = Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=1)
        host2 = Host(vlan=1, mac="00:00:00:00:01:02", port=self.ports[1], tag=1)
        host3 = Host(vlan=1, mac="00:00:00:00:01:03", port=self.ports[2], tag=1)

        self.insert_host_entries([host1, host2, host3])
        do_barrier(self.controller)

        pkt = str(simple_tcp_packet(eth_src=host1.mac,
                                    eth_dst=host2.mac,
                                    dl_vlan_enable=True, vlan_vid=host1.vlan))
        self.dataplane.send(self.ports[2], pkt)
        self.check_no_rx()
        verify_packet_in(self, pkt, self.ports[2], BSN_PACKET_IN_REASON_STATION_MOVE)

class BadVlan(BasePipelineTest):
    """
    Verify that ports may not send on VLANs they don't belong to
    """
    def runTest(self):
        host1 = Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=1)
        host2 = Host(vlan=2, mac="00:00:00:00:02:02", port=self.ports[1], tag=2)

        self.insert_host_entries([host1, host2])
        do_barrier(self.controller)

        pkt = str(simple_tcp_packet(eth_src=host1.mac,
                                    eth_dst=host2.mac,
                                    dl_vlan_enable=True, vlan_vid=2))
        self.dataplane.send(host1.port, pkt)
        self.check_no_rx()
        verify_packet_in(self, pkt, host1.port, BSN_PACKET_IN_REASON_BAD_VLAN)

class DefaultVlan(BasePipelineTest):
    """
    Verify untagged packets get the default VLAN from the port table
    """
    def runTest(self):
        host1 = Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=None)
        host2 = Host(vlan=1, mac="00:00:00:00:01:02", port=self.ports[1], tag=1)

        self.insert_host_entries([host1, host2])
        do_barrier(self.controller)

        in_pkt = str(simple_tcp_packet(eth_src=host1.mac, eth_dst=host2.mac))

        out_pkt = str(simple_tcp_packet(eth_src=host1.mac, eth_dst=host2.mac,
                                        dl_vlan_enable=True, vlan_vid=host1.vlan,
                                        pktlen=104))

        self.dataplane.send(host1.port, in_pkt)
        self.check_rx(host2.port, out_pkt)
        self.check_no_rx()

class UntaggedOutput(BasePipelineTest):
    """
    Verify untagged hosts get stripped packets
    """
    def runTest(self):
        host1 = Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=1)
        host2 = Host(vlan=1, mac="00:00:00:00:01:02", port=self.ports[1], tag=None)

        self.insert_host_entries([host1, host2])
        do_barrier(self.controller)

        in_pkt = str(simple_tcp_packet(eth_src=host1.mac, eth_dst=host2.mac,
                                       dl_vlan_enable=True, vlan_vid=host1.vlan,
                                       pktlen=104))

        out_pkt = str(simple_tcp_packet(eth_src=host1.mac, eth_dst=host2.mac))

        self.dataplane.send(host1.port, in_pkt)
        self.check_rx(host2.port, out_pkt)
        self.check_no_rx()

class UntaggedForwarding(BasePipelineTest):
    """
    Send packets between untagged hosts and verify VLAN isolation
    """
    def runTest(self):
        hosts = [
            Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=None),
            Host(vlan=1, mac="00:00:00:00:01:02", port=self.ports[1], tag=None),
            Host(vlan=2, mac="00:00:00:00:02:03", port=self.ports[2], tag=None),
            Host(vlan=2, mac="00:00:00:00:02:04", port=self.ports[3], tag=None),
        ]

        self.insert_host_entries(hosts)
        do_barrier(self.controller)

        for hostA in hosts:
            for hostB in hosts:
                if hostA is hostB:
                    continue

                expect_success = hostA.vlan == hostB.vlan

                logging.info("Sending from %d/%s to %d/%s. Expecting %s.",
                             hostA.vlan, hostA.mac, hostB.vlan, hostB.mac,
                             expect_success and "success" or "failure")

                pkt = str(simple_tcp_packet(eth_src=hostA.mac, eth_dst=hostB.mac))
                self.dataplane.send(hostA.port, pkt)
                if expect_success:
                    self.check_rx(hostB.port, pkt)
                    self.check_no_rx()
                else:
                    self.check_no_rx()
                    in_pkt = str(simple_tcp_packet(eth_src=hostA.mac, eth_dst=hostB.mac,
                                                   dl_vlan_enable=True, vlan_vid=hostA.vlan,
                                                   pktlen=104))
                    verify_packet_in(self, in_pkt, hostA.port, BSN_PACKET_IN_REASON_DESTINATION_LOOKUP_FAILURE)

class UntaggedBroadcast(BasePipelineTest):
    """
    Send packets to the broadcast address and verify VLAN isolation

    Some destination hosts are untagged.
    """
    def runTest(self):
        host1 = Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=1)
        host2 = Host(vlan=1, mac="00:00:00:00:01:02", port=self.ports[1], tag=1)
        host3 = Host(vlan=1, mac="00:00:00:00:01:03", port=self.ports[2], tag=None)
        host4 = Host(vlan=2, mac="00:00:00:00:02:04", port=self.ports[3], tag=None)

        self.insert_host_entries([host1, host2, host3, host4])
        do_barrier(self.controller)

        pkt = str(simple_tcp_packet(eth_src=host1.mac,
                                    eth_dst="ff:ff:ff:ff:ff:ff",
                                    dl_vlan_enable=True, vlan_vid=host1.vlan,
                                    pktlen=104))

        untagged_pkt = str(simple_tcp_packet(eth_src=host1.mac, eth_dst="ff:ff:ff:ff:ff:ff"))

        self.dataplane.send(host1.port, pkt)
        self.check_rx(host2.port, pkt)
        self.check_rx(host3.port, untagged_pkt)
        self.check_no_rx()

class IngressVlanXlate(BasePipelineTest):
    """
    Verify tagged hosts get ingress VLAN translation
    """
    def runTest(self):
        host1 = Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=300)
        host2 = Host(vlan=1, mac="00:00:00:00:01:02", port=self.ports[1], tag=1)

        self.insert_host_entries([host1, host2])
        do_barrier(self.controller)

        in_pkt = str(simple_tcp_packet(eth_src=host1.mac, eth_dst=host2.mac,
                                       dl_vlan_enable=True, vlan_vid=300,
                                       pktlen=104))

        out_pkt = str(simple_tcp_packet(eth_src=host1.mac, eth_dst=host2.mac,
                                        dl_vlan_enable=True, vlan_vid=host2.vlan,
                                        pktlen=104))

        self.dataplane.send(host1.port, in_pkt)
        self.check_rx(host2.port, out_pkt)
        self.check_no_rx()

class EgressVlanXlate(BasePipelineTest):
    """
    Verify tagged hosts get egress VLAN translation
    """
    def runTest(self):
        host1 = Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=1)
        host2 = Host(vlan=1, mac="00:00:00:00:01:02", port=self.ports[1], tag=400)

        self.insert_host_entries([host1, host2])
        do_barrier(self.controller)

        in_pkt = str(simple_tcp_packet(eth_src=host1.mac, eth_dst=host2.mac,
                                       dl_vlan_enable=True, vlan_vid=host1.vlan,
                                       pktlen=104))

        out_pkt = str(simple_tcp_packet(eth_src=host1.mac, eth_dst=host2.mac,
                                        dl_vlan_enable=True, vlan_vid=400,
                                        pktlen=104))

        self.dataplane.send(host1.port, in_pkt)
        self.check_rx(host2.port, out_pkt)
        self.check_no_rx()

class VlanXlate(BasePipelineTest):
    """
    Verify tagged hosts get ingress and egress VLAN translation
    """
    def runTest(self):
        host1 = Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=300)
        host2 = Host(vlan=1, mac="00:00:00:00:01:02", port=self.ports[1], tag=400)

        self.insert_host_entries([host1, host2])
        do_barrier(self.controller)

        in_pkt = str(simple_tcp_packet(eth_src=host1.mac, eth_dst=host2.mac,
                                       dl_vlan_enable=True, vlan_vid=300,
                                       pktlen=104))

        out_pkt = str(simple_tcp_packet(eth_src=host1.mac, eth_dst=host2.mac,
                                        dl_vlan_enable=True, vlan_vid=400,
                                        pktlen=104))

        self.dataplane.send(host1.port, in_pkt)
        self.check_rx(host2.port, out_pkt)
        self.check_no_rx()

class VlanXlateBroadcast(BasePipelineTest):
    """
    Send packets to the broadcast address and verify VLAN isolation

    Some destination hosts need VLAN translation.
    """
    def runTest(self):
        host1 = Host(vlan=1, mac="00:00:00:00:01:01", port=self.ports[0], tag=1)
        host2 = Host(vlan=1, mac="00:00:00:00:01:02", port=self.ports[1], tag=1)
        host3 = Host(vlan=1, mac="00:00:00:00:01:03", port=self.ports[2], tag=300)
        host4 = Host(vlan=2, mac="00:00:00:00:02:04", port=self.ports[3], tag=300)

        self.insert_host_entries([host1, host2, host3, host4])
        do_barrier(self.controller)

        pkt = str(simple_tcp_packet(eth_src=host1.mac,
                                    eth_dst="ff:ff:ff:ff:ff:ff",
                                    dl_vlan_enable=True, vlan_vid=host1.vlan,
                                    pktlen=104))

        tag300_pkt = str(simple_tcp_packet(eth_src=host1.mac,
                                           eth_dst="ff:ff:ff:ff:ff:ff",
                                           dl_vlan_enable=True, vlan_vid=300,
                                           pktlen=104))

        self.dataplane.send(host1.port, pkt)
        self.check_rx(host2.port, pkt)
        self.check_rx(host3.port, tag300_pkt)
        self.check_no_rx()
