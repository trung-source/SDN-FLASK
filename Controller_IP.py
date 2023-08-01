from ryu.base import app_manager
from ryu.controller import mac_to_port
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER, MAIN_DISPATCHER, DEAD_DISPATCHER, HANDSHAKE_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.ofproto import ofproto_v1_3
from ryu.lib.mac import haddr_to_bin
from ryu.lib.packet import packet
from ryu.lib.packet import arp
from ryu.lib.packet import ethernet
from ryu.lib.packet import ipv4
from ryu.lib.packet import ipv6

from ryu.lib.packet import tcp
from ryu.lib.packet import udp,vxlan,geneve

from ryu.lib.packet import ether_types
from ryu.lib import dpid, mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event

from ryu.lib import dpid as dpid_lib
from collections import defaultdict
from operator import itemgetter, attrgetter, mul


from ryu.lib import hub
from ryu import utils

from ryu.ofproto import ofproto_parser  

import os
import random
import time
import logging

from libovsdb import libovsdb
import json
from ryu.lib.ovs import bridge
from ryu.ofproto import nx_match
import numpy as np

# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 1000000000


DEFAULT_BW = 1000000000
MAX_PATHS = 10


VERBOSE = 0
DEBUGING = 0
SHOW_PATH = 0

ovsdb_server = 'tcp:127.0.0.1:6640'


QOS_CONFIGURED = False
DEFAULT_FLOW_PRIORITY = 0
QOS_TABLE_ID = 0
IDLE_TIMEOUT = 150




# logging.basicConfig(level = logging.INFO)

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.LEARNING = 1
        self.FLAG = 0
        self.request_id = 1
        self.new_request = False
        
        self.topology_api_app = self
        self.datapath_list = {}
        self.arp_table = {}
        self.switches = []
        self.hosts = {}
        self.multipath_group_ids = {}
        self.all_group_id = {}
        self.group_id_count =0
        self.group_ids = []
        self.adjacency = defaultdict(dict)
        self.bandwidths = defaultdict(lambda: defaultdict(lambda: DEFAULT_BW))
        self.sw_port = defaultdict(dict)
        self.count = 0
        self.path_install_cnt =0
        
        self.max_bw = {}
        self.curr_max_bw = {}
        self.sw_reserve_bw = defaultdict(dict)
        self.port_reserve_bw = defaultdict(dict)
        
        self.vx_src_dst = {}
        self.queue_config = {}
        self.min_queue_config = {}
        
        self.request_table= {}
        self.request = {"max-rate":None,"min-rate":None}
        self.vni = None
        self.paths = []
        self.vni_map_src = {}
        self.vni_map_hv = {}
        self.change = False

        
        if DEBUGING == 1:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
            
        
        # monitor
        self.sleep = 1
        # self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.tx_pkt_cur = {}    # currently monitoring TX packets
        self.tx_byte_cur = {}   # currently monitoring TX bytes
        self.tx_pkt_int = {}    # TX packets in the last monitoring interval
        self.tx_byte_int = {}    # TX bytes in the last monitoring interval
        
        
        self.rx_pkt_cur = {}    # currently monitoring TX packets
        self.rx_byte_cur = {}   # currently monitoring TX bytes
        self.rx_pkt_int = {}    # TX packets in the last monitoring interval
        self.rx_byte_int = {}    # TX bytes in the last monitoring interval
    
    def configure_max_qos(self,port):
        ovs_bridge = bridge.OVSBridge(self.CONF, dpid, ovsdb_server)
        self.queue_config.setdefault(port,[])
        self.del_qos_all(port)
        try:
            if self.queue_config[port]:
                ovs_bridge.set_qos(port, type='linux-hfsc',
                                        max_rate=str(DEFAULT_BW),
                                        queues=self.queue_config[port])
            else:
                ovs_bridge.set_qos(port, type='linux-hfsc',
                                        max_rate=str(DEFAULT_BW))
        except Exception as msg:
            raise ValueError(msg)
        
        
    def configure_qos(self,port):
        ovs_bridge = bridge.OVSBridge(self.CONF, dpid, ovsdb_server)
        try:
            if self.queue_config[port]:
                ovs_bridge.set_qos(port, type='linux-hfsc',
                                        max_rate=str(DEFAULT_BW),
                                        queues=self.queue_config[port])
            else:
                ovs_bridge.set_qos(port, type='linux-hfsc',
                                        max_rate=str(DEFAULT_BW))
        except Exception as msg:
            raise ValueError(msg)
    

    # def del_all_qos(self,port):
    #     ovs_bridge = bridge.OVSBridge(self.CONF, dpid, ovsdb_server)
    #     try:
    #         ovs_bridge.del_qos(port)
    #     except Exception as msg:
    #         raise ValueError(msg)
        

    def del_qos_all(self,port):
        db = libovsdb.OVSDBConnection(ovsdb_server, "Open_vSwitch")

        get_port = db.select(table = "Port",
                            columns = ['_uuid',"qos"],
                            where = [["name", "==", port]],)
        port_qos = get_port[0]['qos']


        get_queue = db.select(table = "QoS",
                    columns = ['_uuid',"queues"],
                    where = [["_uuid", "==", ["uuid",port_qos]]])
        
        if not get_queue:
            # self.logger.info("Queue not ref")
            tx = db.transact()
            uuid = port_qos

            tx.delete(table = "QoS",
                    where = [["_uuid", "==", ["uuid",uuid]]])
            tx.mutate(table = "Port",
                        where = [["name", "==", port]],
                        mutations = [tx.make_mutations("qos", "delete", {"uuid": port_qos})])
            response = tx.commit()
                
            
            return

        # QOS ref delete
        tx = db.transact()
        uuid = port_qos

        tx.delete(table = "QoS",
                where = [["_uuid", "==", ["uuid",uuid]]])
        tx.mutate(table = "Port",
                    where = [["name", "==", port]],
                    mutations = [tx.make_mutations("qos", "delete", {"uuid": port_qos})])
        response = tx.commit()

        for queue in get_queue[0]['queues']:
            queue_uuid = queue[1][1]           
            res = db.delete(table = "Queue",
                            where = [["_uuid", "==", ["uuid",queue_uuid]]],
                            referby = ["QoS", port_qos, "queues"])
        return


    # We need to set default queue 0 with maximum bandwithd allow for testing
    # def configure_max_band(self,port):
        # db = libovsdb.OVSDBConnection(ovsdb_server, "Open_vSwitch")
        # res = db.select(table = "Qos",
        #             whehe = {"other-config":"max-rate"})
        # self.logger.info("RES: %s",res)
        
        # if not res:
        #     # self.logger.info("Implement default qos")
        #     self.configure_max_qos(port)
        #     queue = db.insert(table = "Queue",
        #             where = [])
        #     qos = db.insert(table = "Qos",
        #             where = [])
        # self.logger.info("DB: %s",db.list_dbs())
    
        # self.configure_max_qos(port)
    
        
    def get_paths(self, src, dst):
        '''
        Get all paths from src to dst using DFS algorithm    
        '''
        if SHOW_PATH == 1:
            print("################################################")
        if src == dst:
            # host target is on the same switch
            return [[src]]
        paths = []
        stack = [(src, [src])]
        
        if VERBOSE == 1:
            print("--stack",stack)
            print("---adjacency",self.adjacency)
            
        while stack:
            # stack pop the last item => LIFO
            (node, path) = stack.pop()
            
            if VERBOSE == 1:
                print((node, path))
                # set is sorted
                print("---adjacency[",node,']:',self.adjacency[node].keys())
                
            for next in set(self.adjacency[node].keys()) - set(path):
                if next is dst:
                    paths.append(path + [next])
                    
                    if VERBOSE == 1:
                        print("-paths",paths)
                else:
                    stack.append((next, path + [next]))
                    
                    if VERBOSE == 1:
                        print("--stack",stack)
        if SHOW_PATH == 1:
            print("################################################")
            print("Available paths from ", src, " to ", dst, " : ", paths)
        
        return paths


    def get_link_cost(self, s1, s2):
        '''
        Get the link cost between two switches 
        '''
        e1 = self.adjacency[s1][s2]
        e2 = self.adjacency[s2][s1]
        
        
        if not self.tx_byte_int.setdefault(s1,{}) or not self.tx_byte_int.setdefault(s2,{}):
            # bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
            return 0
        if not self.rx_byte_int.setdefault(s1,{}) or not self.rx_byte_int.setdefault(s2,{}):
            # bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
            return 0
            
    
            # bl = min(self.tx_byte_int[s1][e1], self.tx_byte_int[s2][e2])
        ew = (self.tx_byte_int[s1][e1]+self.tx_byte_int[s2][e2])*8
        
        # can use both way to calculate bw (ew and ew2)
        # ew2 = (self.tx_byte_int[s1][e1]+self.rx_byte_int[s1][e1])*8
        
        # self.logger.info("ew: %s\n ew2: %s"%(ew,ew2))
        
        return ew

    def get_host_link_cost(self, port, dpid):
        '''
        Get the link cost between switch and host
        '''
        
        
        if not self.tx_byte_int.setdefault(dpid,{}):
            # bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
            ew = 0
        
        if not self.rx_byte_int.setdefault(dpid,{}):
            # bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
            ew = 0
            
        else:
            # VM send 1 traffic to switch port but many traffic from other VMs 
            # come from 1 switch port
            ew = (self.tx_byte_int[dpid][port]+self.rx_byte_int[dpid][port])*8
        return ew
    
    def get_link_bw_available(self, s1, s2):
        '''
        Get the bw availalbe between  switch and host
        '''
        e1 = self.adjacency[s1][s2]
        e2 = self.adjacency[s2][s1]
        
        self.min_queue_config.setdefault(s2,{})
        self.min_queue_config.setdefault(s2,{})
            # bl = min(self.tx_byte_int[s1][e1], self.tx_byte_int[s2][e2])
        self.min_queue_config[s1].setdefault(e1,0)
        self.min_queue_config[s2].setdefault(e2,0)
        # ew = self.min_queue_config[s1][e1]+self.min_queue_config[s2][e2]
        ew = DEFAULT_BW-self.min_queue_config[s1][e1]
        
        return ew

    def get_host_link_bw_available(self, port, dpid):
        '''
        Get the bw availbe between host and switch
        '''
        self.min_queue_config.setdefault(dpid,{})
        self.min_queue_config[dpid].setdefault(port,0)
        # VM send 1 traffic to switch port but many traffic from other VMs 
        # come from 1 switch port
        ew = DEFAULT_BW-self.min_queue_config[dpid][port]
        return ew

    def get_path_cost(self, path,first_port,last_port):
        '''
        Get the path cost
        '''
        cost = 0
        for i in range(len(path) - 1):
            cost += self.get_link_cost(path[i], path[i+1])
        cost += self.get_host_link_cost(first_port, path[0])
        cost += self.get_host_link_cost(last_port, path[-1])
        return cost
    
    
    def get_path_cost_qos(self, path,first_port,last_port):
        '''
        Get the path cost
        '''
        cost = []
        cost.append(self.get_host_link_bw_available(first_port, path[0]))
        for i in range(len(path) - 1):
            cost.append(self.get_link_bw_available(path[i], path[i+1]))
            
        cost.append(self.get_host_link_bw_available(last_port, path[-1]))
                    
        return cost
    

    def sorted_path(self,paths,pw):
        # sorted paths based on pw
        zip_list = zip(pw,paths)
        sorted_zip_list = sorted(zip_list)
        sorted_list = [e for _, e in sorted_zip_list]
       
        # self.logger.info("sorted:%s",
        #                 sorted_list)
        return sorted_list
             
                
    def get_optimal_paths(self, src, dst,first_port,last_port):
        '''
        Get the n-most optimal paths according to MAX_PATHS
        '''
        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path,first_port,last_port))
        # print(sorted(paths, key=lambda x: self.get_path_cost(path)[0:(paths_count)]
        # return sorted(paths, key=lambda x: self.sorted_path(x,paths,pw))[0:(paths_count)],pw[0:(paths_count)]
        return self.sorted_path(paths,pw)[0:(paths_count)],sorted(pw[0:(paths_count)])

    def get_optimal_paths_qos(self, src, dst,first_port,last_port):
        '''
        Get the n-most optimal paths according to MAX_PATHS
        '''
        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        pw = []
        for path in paths:
            pw.append(self.get_path_cost_qos(path,first_port,last_port))
        # print(sorted(paths, key=lambda x: self.get_path_cost(path)[0:(paths_count)]
        # return sorted(paths, key=lambda x: self.sorted_path(x,paths,pw))[0:(paths_count)],pw[0:(paths_count)]
        return self.sorted_path(paths,pw)[0:(paths_count)],sorted(pw[0:(paths_count)])
    
    def add_ports_to_paths(self, paths, first_port, last_port):
        '''
        Add the ports that connects the switches for all paths
        '''
        paths_p = []
        for path in paths:
            p = {}
            in_port = first_port
            # print("-----")
            # print(path[:-1],"\n", path[1:])
            for s1, s2 in zip(path[:-1], path[1:]):
                out_port = self.adjacency[s1][s2]
                # print('s',s1,s2,out_port)
                p[s1] = (in_port, out_port)
                in_port = self.adjacency[s2][s1]
            p[path[-1]] = (in_port, last_port)
            paths_p.append(p)
            
            
            
        # print(paths_p)
        return paths_p


    def generate_openflow_gid(self,src,dst):
        '''
        Returns a random OpenFlow group id
        '''
        n = self.group_id_count + 1
        
        while n in self.group_ids:
            n = n + 1
        if n < 10:
            s = "{}".format(n)
        if n>=10:
            s = "{}".format(n)
        
        self.group_ids.append(n)
        return int(s)



    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst,ip_proto,vx_src,vx_dst,src_port,dst_port,src_ip,dst_ip,vni):
        # if SHOW_PATH == 1:
        #     self.path_install_cnt +=1
            # self.logger.info("installing path cnt: %d" % (self.path_install_cnt))
        self.LEARNING = 1
        computation_start = time.time()
        paths,pw = self.get_optimal_paths(src, dst, first_port, last_port)
        # self.logger.info("paths:%s\n"
        #                  "pw:%s\n"
        #                  ,paths,pw)
        
        # self.logger.info(
        #                  "pw:%s\n"
        #                  ,pw)

            
        # paths = paths[0]
        pw = pw[0]
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        paths_with_ports = paths_with_ports[0]
        
        
        switches_in_paths = set().union(*paths)
        # print(switches_in_paths)
        if VERBOSE == 1:
            print(paths_with_ports)
            # print(pw)
            print("#adjacency",self.adjacency)

        for node in paths[0]:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser


            # pw is total cost of a path (path weight)
            # ports contain inport:(outport,pw)
            ports = defaultdict(list)
            actions = []
        


      
            if node in paths_with_ports:
                in_port = paths_with_ports[node][0]
                out_port = paths_with_ports[node][1]
                if (out_port, pw) not in ports[in_port]:
                    ports[in_port].append((out_port, pw))
        
            if VERBOSE == 1:
                print("-------------------------------")
                print("\tnode {}: ports{}".format(node,ports) ) 

            for in_port in ports:
                out_ports = ports[in_port]
                actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]
                # self.logger.info("VNI: %s"%vni)
                # match_arp = ofp_parser.OFPMatch(
                #         eth_type=0x0806, 
                #         arp_spa=ip_src, 
                #         arp_tpa=ip_dst
                #     )
                if ip_proto == 1:
                # Ipv4
                    match_icmp = ofp_parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=1,
                            
                        ipv4_src=ip_src, 
                        ipv4_dst=ip_dst,
                    )
                    self.add_flow(dp, 3, match_icmp, actions,IDLE_TIMEOUT)        

                    # ARP
                    # match_vni= ofp_parser.OFPMatch(
                    # eth_type_nxm=0x0800, 
                    # # in_port_nxm = in_port,
                    # # ip_proto_nxm=17,
                    # # tunnel_id = vni,
                    # ipv4_src=ip_src, 
                    # ipv4_dst=ip_dst,
                    # metadata = 0x05
                    # )
                    # self.add_flow(dp, 8, match_vni, actions,IDLE_TIMEOUT)

                    
                if ip_proto == 6:
                    match_tcp = ofp_parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=6,
                        ipv4_src=ip_src, 
                        ipv4_dst=ip_dst
                        # tcp_dst=dst_port
                    )
                    self.add_flow(dp, 10, match_tcp, actions,IDLE_TIMEOUT)

    
                elif ip_proto == 17:
                    # BDF traffic
                    if vni == 0:
                        match_vni= ofp_parser.OFPMatch(
                        eth_type_nxm=0x0800, 
                        # in_port_nxm = in_port,
                        ip_proto_nxm=17,
                        ipv4_src=ip_src, 
                        ipv4_dst=ip_dst,
                        udp_src_nxm=src_port,
                        udp_dst_nxm=dst_port,    
                        )
                        if vx_src == "arp":
                            self.add_flow(dp, 4, match_vni, actions,IDLE_TIMEOUT)
                        else:
                            self.add_flow(dp, 8, match_vni, actions,IDLE_TIMEOUT)
                    else:
                        match_vni= ofp_parser.OFPMatch(
                            eth_type_nxm=0x0800, 
                            # in_port_nxm = in_port,
                            ip_proto_nxm=17,
                            ipv4_src=ip_src, 
                            ipv4_dst=ip_dst,
                            udp_src_nxm=src_port,
                            udp_dst_nxm=dst_port,
                            # tunnel_id=int(vni)

                        )
                        if vx_src == "arp" or vx_dst == "arp":
                            self.add_flow(dp, 4, match_vni, actions,IDLE_TIMEOUT)
                        else:
                            self.add_flow(dp, 12, match_vni, actions,IDLE_TIMEOUT)

        # print("Path installation finished in ", time.time() - computation_start )
        # print(paths_with_ports[0][src][1])
        return paths_with_ports[src][1]
    
    def install_paths_arp(self, src, first_port, dst, last_port, ip_src, ip_dst,ip_proto,dst_port,src_ip,dst_ip,vni):
        # if SHOW_PATH == 1:
        #     self.path_install_cnt +=1
            # self.logger.info("installing path cnt: %d" % (self.path_install_cnt))
        self.LEARNING = 1
        computation_start = time.time()
        paths,pw = self.get_optimal_paths(src, dst,first_port,last_port)
        # self.logger.info("paths:%s\n"
        #                  "pw:%s\n"
        #                  ,paths,pw)

        # paths = paths[0]
        pw = pw[0]

        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        paths_with_ports = paths_with_ports[0]
        
        
        switches_in_paths = set().union(*paths)
        # print(switches_in_paths)
        if VERBOSE == 1:
            print(paths_with_ports)
            # print(pw)
            print("#adjacency",self.adjacency)

        for node in paths[0]:

            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser


            # pw is total cost of a path (path weight)
            # ports contain inport:(outport,pw)
            ports = defaultdict(list)
            actions = []
        
            if node in paths_with_ports:
                in_port = paths_with_ports[node][0]
                out_port = paths_with_ports[node][1]
                if (out_port, pw) not in ports[in_port]:
                    ports[in_port].append((out_port, pw))
        
            if VERBOSE == 1:
                print("-------------------------------")
                print("\tnode {}: ports{}".format(node,ports) ) 

            for in_port in ports:
                # ARP
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )
            
                out_ports = ports[in_port]
                # elif len(out_ports) == 1:
                actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]
                # self.add_flow(dp, 3, match_ip, actions,IDLE_TIMEOUT)
                self.add_flow(dp, 1, match_arp, actions,IDLE_TIMEOUT)
        # print("Path installation finished in ", time.time() - computation_start )
        # print(paths_with_ports[0][src][1])
        return paths_with_ports[src][1]

    def install_replace_paths(self, src, first_port, dst, last_port, ip_src, ip_dst,p,cost):
        if SHOW_PATH == 1:
            self.path_install_cnt +=1
            self.logger.info("installing path cnt: %d" % (self.path_install_cnt))
        self.LEARNING = 1
        computation_start = time.time()
        # paths,pw = self.get_optimal_paths(src, dst)
        paths = p
        pw = cost
        pw = pw[0]         
        
        paths_with_ports = self.add_ports_to_paths(paths, first_port, last_port)
        paths_with_ports = paths_with_ports[0]
        switches_in_paths = set().union(*paths)
        # print(switches_in_paths)
        if VERBOSE == 1:
            print(paths_with_ports)
            # print(pw)
            print("#adjacency",self.adjacency)

        for node in switches_in_paths:
            dp = self.datapath_list[node]
            ofp = dp.ofproto
            ofp_parser = dp.ofproto_parser

            # pw is total cost of a path (path weight)
            # ports contain inport:(outport,pw)
            ports = defaultdict(list)
            actions = []

            if node in paths_with_ports:
                in_port = paths_with_ports[node][0]
                out_port = paths_with_ports[node][1]
                if (out_port, pw) not in ports[in_port]:
                    ports[in_port].append((out_port, pw))
 
            if VERBOSE == 1:
                print("-------------------------------")

            for in_port in ports:
                out_ports = ports[in_port]
            
                # print("_MODOUTPORT",ports)
                
                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst
                )
            
                # ARP
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )
                                
                actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]

                self.add_flow(dp, 32768, match_ip, actions)
                self.add_flow(dp, 1, match_arp, actions)
        return 
    
    
        
    def add_flow(self, datapath, priority, match, actions, idle_timeout=None, buffer_id=None,insts=None,table_id=0):
        # print "Adding flow ", match, actions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if insts:
            inst.append(insts)
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,idle_timeout=idle_timeout,
                                    priority=priority, match=match,
                                    instructions=inst,table_id=table_id)

        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst,table_id=table_id)
        datapath.send_msg(mod)
        
    def add_flow(self, datapath, priority, match, actions, idle_timeout=0, buffer_id=None,insts=None,table_id=0):
        # print "Adding flow ", match, actions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if insts:
            inst.append(insts)
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,idle_timeout=idle_timeout,
                                    priority=priority, match=match,
                                    instructions=inst,table_id=table_id)

        else:
            mod = parser.OFPFlowMod(datapath=datapath,idle_timeout=idle_timeout, priority=priority,
                                    match=match, instructions=inst,table_id=table_id)
        datapath.send_msg(mod)
    
    @set_ev_cls(ofp_event.EventOFPErrorMsg,
    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def error_msg_handler(self, ev):
        msg = ev.msg
        ofp = msg.datapath.ofproto
        self.logger.debug(
            "EventOFPErrorMsg received.\n"
            "version=%s, msg_type=%s, msg_len=%s, xid=%s\n"
            " `-- msg_type: %s\n"
            "OFPErrorMsg(type=%s, code=%s, data=b'%s')\n"
            " |-- type: %s\n"
            " |-- code: %s\n"
            " |-- dpid: %s\n"
            ,
            
            hex(msg.version), hex(msg.msg_type), hex(msg.msg_len),
            hex(msg.xid), ofp.ofp_msg_type_to_str(msg.msg_type),
            hex(msg.type), hex(msg.code), utils.binary_str(msg.data),
            ofp.ofp_error_type_to_str(msg.type),
            ofp.ofp_error_code_to_str(msg.type, msg.code),
            msg.datapath.id)
        if msg.type == ofp.OFPET_HELLO_FAILED:
            self.logger.debug(
                " `-- data: %s", msg.data.decode('ascii'))
        elif len(msg.data) >= ofp.OFP_HEADER_SIZE:
            (version, msg_type, msg_len, xid) = ofproto_parser.header(msg.data)
            self.logger.debug(
                " `-- data: version=%s, msg_type=%s, msg_len=%s, xid=%s\n"
                "     `-- msg_type: %s",
                hex(version), hex(msg_type), hex(msg_len), hex(xid),
                ofp.ofp_msg_type_to_str(msg_type))
        else:
            self.logger.warning(
                "The data field sent from the switch is too short: "
                "len(msg.data) < OFP_HEADER_SIZE\n"
                "The OpenFlow Spec says that the data field should contain "
                "at least 64 bytes of the failed request.\n"
                "Please check the settings or implementation of your switch.")

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def _switch_features_handler(self, ev):
        print("switch_features_handler is called")
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER,
                                          ofproto.OFPCML_NO_BUFFER)]
        self.delete_all_flow(datapath,0)
        self.delete_all_flow(datapath,1)

        self.add_flow(datapath, 0, match, actions)


    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        for p in ev.msg.body:
            # self.bandwidths[switch.id][p.port_no] = p.curr_speed
            self.bandwidths[switch.id][p.port_no] = DEFAULT_BW
            # if p.curr_speed > 0 :
            #     port = p.name.decode("utf-8")
                # self.logger.info("name: %s",port)
                
                # No need to configure max qos in Controller port
                # if p.port_no != 4294967294:
                #     self.configure_max_qos(port)
                    # self.QOS_FLAG = True


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # self.logger.info("PACKETIN %d" % (self.count))
        # self.count += 1
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match['in_port']


        pkt = packet.Packet(msg.data)
        eth = pkt.get_protocol(ethernet.ethernet)
        arp_pkt = pkt.get_protocol(arp.arp)


        # avoid broadcast from LLDP
        if eth.ethertype == 35020:
            return


        if pkt.get_protocol(ipv6.ipv6):  # Drop the IPV6 Packets.
            match = parser.OFPMatch(eth_type=eth.ethertype)
            actions = []
            self.add_flow(datapath, 1, match, actions)
            return None


        dst = eth.dst
        src = eth.src
        dpid = datapath.id


        if src not in self.hosts:
            self.hosts[src] = (dpid, in_port)
            if VERBOSE == 1:
                print("-----------------------------------")
                print("\t\tHost_learned: ",self.hosts)
                print("-----------------------------------")

        out_port = ofproto.OFPP_FLOOD

        ip_pkt = pkt.get_protocol(ipv4.ipv4)
        
        ipvx_dst = None
        ipvx_src = None
        
        vx_lan = 0
        src_port = 0
        dst_port = 0
        ip_proto = -1
        vni = -1
        options = None
        
                
            
           
        
        if arp_pkt:
            self.LEARNING = 1
            # print dpid, pkt
            if VERBOSE == 1:
                print("datapath id: "+str(dpid))
                print("port: "+str(in_port))
                print(("pkt_eth.dst: " + str(eth.dst)))
                print(("pkt_eth.src: " + str(eth.src)))
                print(("pkt_arp: " + str(arp_pkt)))
                print(("pkt_arp:src_ip: " + str(arp_pkt.src_ip)))
                print(("pkt_arp:dst_ip: " + str(arp_pkt.dst_ip)))
                print(("pkt_arp:src_mac: " + str(arp_pkt.src_mac)))
                print(("pkt_arp:dst_mac: " + str(arp_pkt.dst_mac)))
                # dst_mac will be 00:00:00:00:00:00 when host is unknown (ARPRequest)
            
            src_ip = arp_pkt.src_ip
            dst_ip = arp_pkt.dst_ip
            
            
            
            
            if arp_pkt.opcode == arp.ARP_REPLY:
                # ARP table IP - MAC
                self.arp_table[src_ip] = src
                h1 = self.hosts[src]
                h2 = self.hosts[dst]
                # self.logger.info("VXPORT %s"%vx_dst_port)
                
                #Install path: dpid src, src in_port, dpid dst, dpid in_port, src_ip, dst_ip
                if VERBOSE == 1:
                    print("Installing: Src:{}, Src in_port{}. Dst:{}, Dst in_port:{}, Src_ip:{}, Dst_ip:{}".format(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip,dst_port))
                out_port = self.install_paths_arp(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip,ip_proto,dst_port,src_ip, dst_ip, vni)
                self.install_paths_arp(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip,ip_proto,dst_port,src_ip, dst_ip, vni) # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    # print("dst_ip found in arptable")
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.install_paths_arp(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip,ip_proto,dst_port,src_ip, dst_ip, vni)
                    self.install_paths_arp(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip,ip_proto,dst_port,src_ip, dst_ip, vni) # reverse
            if VERBOSE == 1:
                print("--arptable",self.arp_table)
        # print pkt
        # else:
        #     # print("notARP",pkt)
        #     pass

        if isinstance(ip_pkt, ipv4.ipv4):
            # print("IPIP")
            # load balancing based on traffic monitoring
            
            
            ip_proto = ip_pkt.proto
            # print("ip_pkt",ip_pkt)
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            
            
            if ip_proto == 6:
                # TCP
                # self.logger.info("Switch %s: TCP packet", dpid)
                tcp_pkt = pkt.get_protocol(tcp.tcp)
                # print("tcp_pkt",tcp_pkt)
                dst_port = tcp_pkt.dst_port
                src_port = tcp_pkt.src_port
                
       
                
            elif ip_proto == 17:
                # UDP
                # self.logger.debug("Switch %s: UDP packet", dpid)
                udp_pkt = pkt.get_protocol(udp.udp)
                # print("udp_pkt",udp_pkt)
            
                
                dst_port = udp_pkt.dst_port
                src_port = udp_pkt.src_port
                if dst_port == 6081:
                
                    # self.logger.info("UDP PKT: %s"%udp_pkt)
                    vxlan_pkt = pkt.get_protocol(geneve.geneve)
                    vni = vxlan_pkt.vni
                    options = vxlan_pkt.options
                    payload_pkt = pkt[4:]
                    # payload_pkt = packet.Packet(payload_pkt)                 
       
                    ethvx_src = payload_pkt[0].src
                    ethvx_dst = payload_pkt[0].dst
                    ethertype = payload_pkt[0].ethertype

                    self.logger.info("\tvxlan_pkt PKT: %s" % pkt)
                    
                    if (ethertype==0x800):
                        ipvx_src = payload_pkt[1].src
                        ipvx_dst = payload_pkt[1].dst
                        
                        try:
                            protovx = payload_pkt[1].proto
                            portvx_src = payload_pkt[2].src_port
                            portvx_dst = payload_pkt[2].dst_port
                        except:
                            portvx_src = 0
                            portvx_dst = 0
                        self.logger.info("\tproto inner: %s" %protovx)
                        self.logger.info("\tsrc port inner: %s" %portvx_src)
                        self.logger.info("\tdst port inner: %s" %portvx_dst)

                        if vni not in self.vni_map_src.keys():
                            self.vni_map_src[vni] = {}
                            self.vni_map_src[vni].setdefault((ipvx_src,ipvx_dst))
                            self.vni_map_src[vni][(ipvx_src,ipvx_dst)] = {}
                            self.vni_map_src[vni][(ipvx_src,ipvx_dst)].setdefault((protovx,portvx_src,portvx_dst))
                            self.vni_map_src[vni][(ipvx_src,ipvx_dst)][(protovx,portvx_src,portvx_dst)] = src_port

                        elif (ipvx_src,ipvx_dst) not in self.vni_map_src[vni].keys():
                            self.vni_map_src[vni][(ipvx_src,ipvx_dst)] = {}
                            self.vni_map_src[vni][(ipvx_src,ipvx_dst)].setdefault((protovx,portvx_src,portvx_dst))
                            self.vni_map_src[vni][(ipvx_src,ipvx_dst)][(protovx,portvx_src,portvx_dst)] = src_port
                        
                        elif (protovx,portvx_src,portvx_dst) not in self.vni_map_src[vni][(ipvx_src,ipvx_dst)].keys():
                            self.vni_map_src[vni][(ipvx_src,ipvx_dst)][(protovx,portvx_src,portvx_dst)] = src_port
                                


                        if src_ip not in self.vni_map_hv.keys():
                            self.vni_map_hv[src_ip] = {}
                            self.vni_map_hv[src_ip][vni] = []
                            self.vni_map_hv[src_ip][vni].append(ipvx_src)
                        elif vni not in self.vni_map_hv[src_ip].keys():
                            self.vni_map_hv[src_ip][vni] = []
                            self.vni_map_hv[src_ip][vni].append(ipvx_src)
                        elif ipvx_src not in self.vni_map_hv[src_ip][vni]:
                            self.vni_map_hv[src_ip][vni].append(ipvx_src)
                    

                        # self.logger.info("\tGeneve options: %s" % options)
                        self.logger.info("\tvni: %s" % vni)
                        self.logger.info("\tipvx_src: %s" % ipvx_src)
                        self.logger.info("\tipvx_dst: %s" % ipvx_dst)
                        self.logger.info("vni_map_src: %s" % self.vni_map_src[vni])

                    elif(ethertype==0x806):
                        ipvx_src = payload_pkt[1].src_ip
                        # if vni not in self.vni_map_src.keys():
                        #     self.vni_map_src[vni] = {}
                        self.logger.info("\vni_map_src arp--: %s : %s" % (ipvx_src,src_port))
                        ipvx_src = "arp"
                        ipvx_dst = "arp"
                    else:
                        self.logger.info("\vni_map_src ??--: %s" % (vxlan_pkt))
                        
                    # self.logger.info(self.vx_src_dst)
                    self.logger.info("vni_map_src: %s" % self.vni_map_src)
                    self.logger.info("vni_map_hv: %s" % self.vni_map_hv)
                    # self.logger.info("sw_port: %s" % self.sw_port)
                    # self.logger.info("request: %s" % self.request_table)






                elif dst_port == 4789 or dst_port == 8472:
             
                    # self.logger.info("UDP PKT: %s"%udp_pkt)
                    vxlan_pkt = pkt.get_protocol(vxlan.vxlan)
                    vni = vxlan_pkt.vni
                    payload_pkt = pkt[4:]
                    # payload_pkt = packet.Packet(payload_pkt)
                    
                    # pkt_payload = payload_pkt.get_protocol(ipv4.ipv4)
                    # self.logger.info("\tvxlan_pkt PKT: %s" % payload_pkt)
                    
                    ethvx_src = payload_pkt[0].src
                    ethvx_dst = payload_pkt[0].dst
                    
                    
                    ipvx_src = payload_pkt[1].src
                    ipvx_dst = payload_pkt[1].dst
                    
                    self.vx_src_dst.setdefault(ipvx_src,[])
                    if ipvx_dst not in self.vx_src_dst[ipvx_src]:
                        self.vx_src_dst[ipvx_src].append(ipvx_dst)
                        self.logger.info("vxlan_pkt PKT: %s" % vxlan_pkt)
                        # self.logger.info("vxlan_pkt PKT: %s" % self.vx_src_dst)
                        
                        
                        self.logger.info("\tipvx src: %s\t ipvx dst: %s" % (ipvx_src,ipvx_dst))
             
                    
        
        if isinstance(ip_pkt,ipv4.ipv4):
            src_ip = ip_pkt.src
            dst_ip = ip_pkt.dst
            self.arp_table[src_ip] = src
            if dst_ip in self.arp_table:
                dst_mac = self.arp_table[dst_ip]
                h1 = self.hosts[src]
                h2 = self.hosts[dst_mac]
                # self.logger.info("VXPORT %s"%vx_dst_port)
                
                #Install path: dpid src, src in_port, dpid dst, dpid in_port, src_ip, dst_ip
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip,ip_proto,ipvx_src,ipvx_dst,src_port,dst_port,src_ip, dst_ip, vni,)
                # self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip,ip_proto,ipvx_dst,ipvx_src,dst_port,src_port,src_ip, dst_ip, vni, options) # reverse
         
            
        
        actions = [parser.OFPActionOutput(out_port)]


        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data


        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
        self.LEARNING = 0
            

        

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser
        ports = ev.switch.ports
        
        # self.logger.info("ALL_SW: %s",ev.switch)
        
        if VERBOSE == 1:
            print("Switch In: ",switch.id)

        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch
            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)

            for port in ports:
                port_name = port.name.decode('utf-8')
                self.sw_port[switch.id][port.port_no] = port_name
            # No need to configure max qos in Controller port
                if port.port_no != 4294967294:
                    self.configure_max_qos(port_name)
            
        
        # self.logger.info("ALL_SW: %s",self.sw_port)

    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        print(ev)
        switch = ev.switch.dp.id
        if switch in self.switches:
            self.switches.remove(switch)
            del self.datapath_list[switch]
            del self.adjacency[switch]
            try:
                del self.sw_port[switch]
            except:
                pass

    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no
        


        
    def _monitor(self):
        while True:
            for dp in self.datapath_list.values():
                self._request_stats(dp)
                # print("START OF {} SECONDS!!!".format(self.sleep))
            hub.sleep(self.sleep)

    def _request_stats(self, datapath):
        self.logger.debug('send stats request: %016x', datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        
        #Send PortStatsRequest
        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def delete_all_flow(self, datapath, table_id):   
        """Removing all flow entries."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        empty_match = parser.OFPMatch()
        instructions = []
        
        # Del/Mod flow table, group table
        flow_mod = self.remove_table_flows(datapath, table_id,
                                        empty_match, instructions)
        print("deleting all flow entries in table ", table_id)   
        datapath.send_msg(flow_mod)
        
        
    def delete_flow(self, datapath, table_id,match):   
        """Removing all flow entries."""
        parser = datapath.ofproto_parser
        ofproto = datapath.ofproto
        empty_match = parser.OFPMatch(match)
        instructions = []
        
        # Del/Mod flow table, group table
        flow_mod = self.remove_table_flows(datapath, table_id,
                                        empty_match, instructions)
        print("deleting flow entries in table ", table_id)   
        datapath.send_msg(flow_mod)
    
    def remove_table_flows(self, datapath, table_id, match, instructions):
        """Create OFP flow mod message to remove flows from table."""
        ofproto = datapath.ofproto
        flow_mod = datapath.ofproto_parser.OFPFlowMod(datapath, 0, 0, table_id,
                                                      ofproto.OFPFC_DELETE, 0, 0,
                                                      1,
                                                      ofproto.OFPCML_NO_BUFFER,
                                                      ofproto.OFPP_ANY,
                                                      ofproto.OFPG_ANY, 0,
                                                      match, instructions)
        return flow_mod
        
    def send_group_mod(self, datapath):
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        
        if not self.all_group_id or not self.all_group_id.setdefault(datapath.id,{}):
            return
        else:
            for group_id in self.all_group_id[datapath.id].keys():
                #buckets
                buckets = []
                for port in self.all_group_id[datapath.id][group_id].keys():
                    bucket_weight = self.all_group_id[datapath.id][group_id][port] 
                    bucket_action = [ofp_parser.OFPActionOutput(port)]
                    # bucket_action = []
                    buckets.append(
                                    ofp_parser.OFPBucket(
                                        weight=bucket_weight,
                                        watch_port=port,
                                        watch_group=ofp.OFPG_ANY,
                                        actions=bucket_action
                                    )
                                )
                   
                    self.logger.info("dataid:%d gid:%d port:%d bucketw:%d buckets %s" 
                                        %(datapath.id,group_id,port,bucket_weight,buckets))
        
                req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_MODIFY, ofp.OFPGT_SELECT, group_id)  
                datapath.send_msg(req)
        
    def delete_group_mod(self, datapath):

        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        if not self.all_group_id or not self.all_group_id.setdefault(datapath.id,{}):
            return
        else:
            for group_id in self.all_group_id[datapath.id].keys():
                #buckets
                req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_DELETE, 0, group_id)  
                datapath.send_msg(req)
            del self.all_group_id[datapath.id]   

    def banwidth_calculation_host(self,dpid):
        hosts = self.get_host_from_dpid(dpid)
        # self.logger.info("Host: %s",hosts)
        for host in hosts:
            h_temp = self.hosts[host]
            h_temp_name = self.sw_port[dpid][h_temp[1]]
            bl = (self.tx_byte_int[dpid][h_temp[1]]+self.rx_byte_int[dpid][h_temp[1]])*8
            self.port_reserve_bw[dpid][h_temp_name] = DEFAULT_BW - bl
            
    
            
    def banwidth_calculation(self,dpid):
        for dst in self.switches:
            try:
                e1 = self.adjacency[dpid][dst]
                e2 = self.adjacency[dst][dpid]
            except:
                continue
            try:
                bl = (self.tx_byte_int[dpid][e1]+self.tx_byte_int[dst][e2])*8
                reserve = DEFAULT_BW - bl
                self.sw_reserve_bw[dpid][dst] = reserve
                self.sw_reserve_bw[dst][dpid] = reserve
                
                e1_name = self.sw_port[dpid][e1]
                e2_name = self.sw_port[dst][e2]
                
                
                self.port_reserve_bw[dpid][e1_name] = reserve
                self.port_reserve_bw[dst][e2_name] = reserve
                
                self.banwidth_calculation_host(dpid)
                
                if VERBOSE == 1 and dpid == 1:
                    self.logger.info("BW1: %s \nBw2: %s" %(self.tx_byte_int[dpid][e1],self.tx_byte_int[dst][e2]))
            except:
                continue
    
    def mod_qos_paths(self,node,vni,src_ip,dst_ip,out_port,queue_id,vm_traffic):
        datapath = self.datapath_list[node]
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(out_port)]

        actions_queue = [ofp_parser.OFPActionSetQueue(queue_id)]
        actions_queue.append(ofp_parser.OFPActionOutput(out_port))
        
        
        match_arp = ofp_parser.OFPMatch(
                        eth_type=0x0806, 
                        arp_spa=src_ip, 
                        arp_tpa=dst_ip
                    )
        
        match_icmp = ofp_parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=1,
                         
                        ipv4_src=src_ip, 
                        ipv4_dst=dst_ip,
                    )

        match_tcp = ofp_parser.OFPMatch(
                        eth_type=0x0800, 
                        ip_proto=6,
                        ipv4_src=src_ip, 
                        ipv4_dst=dst_ip
                    )
        
        # match_udp = ofp_parser.OFPMatch(
        #                 eth_type=0x0800, 
        #                 ip_proto=17,
        #                 ipv4_src=src_ip, 
        #                 ipv4_dst=dst_ip
        #             )
        if vm_traffic:
            vni = int(vni)
            ipvx_src = vm_traffic[0]
            ipvx_dst = vm_traffic[1]
            for port in self.vni_map_src[vni][ipvx_src,ipvx_dst].values():
                src_port =  port
                match_vni = ofp_parser.OFPMatch(
                                eth_type=0x0800, 
                                ip_proto=17,
                                ipv4_src=src_ip, 
                                ipv4_dst=dst_ip,
                                udp_src=src_port,
                                udp_dst=6081,
                                # tunnel_id = int(vni)
                            )
                self.add_flow(datapath, 12, match_vni, actions_queue,IDLE_TIMEOUT)
        elif vni is not None:
            vni = int(vni)
            ipvx_src_list = self.vni_map_hv[src_ip][vni]
            ipvx_dst_list = self.vni_map_hv[dst_ip][vni]
            for ipvx_src in ipvx_src_list:
                for ipvx_dst in ipvx_dst_list:
                    for port in self.vni_map_src[vni][ipvx_src,ipvx_dst].values():
                        src_port = port
                        match_vni = ofp_parser.OFPMatch(
                                        eth_type=0x0800, 
                                        ip_proto=17,
                                        ipv4_src=src_ip, 
                                        ipv4_dst=dst_ip,
                                        udp_src=src_port,
                                        udp_dst=6081,
                                        # tunnel_id = int(vni)
                                    )
                        if vni == 0:
                            self.add_flow(datapath, 8, match_vni, actions_queue,IDLE_TIMEOUT)
                        else:
                            self.add_flow(datapath, 12, match_vni, actions_queue,IDLE_TIMEOUT)

        else:
            match_ip = ofp_parser.OFPMatch(
                            eth_type=0x0800, 
                            ipv4_src=src_ip, 
                            ipv4_dst=dst_ip
                            # tunnel_id = int(vni)
                        )
            self.add_flow(datapath, 2, match_ip, actions_queue,IDLE_TIMEOUT)
                                     
        self.add_flow(datapath, 3, match_icmp, actions,IDLE_TIMEOUT)
                
        
        self.add_flow(datapath, 10, match_tcp, actions,IDLE_TIMEOUT)
        # self.add_flow(datapath, 10, match_udp, actions,IDLE_TIMEOUT)
        
                    
        self.add_flow(datapath, 1, match_arp , actions,IDLE_TIMEOUT)
        

    
    def accept_demand(self,request,path,dst_port,vni,src_ip,dst_ip,vm_traffic):
        for i in range(len(path)-1):
            s1 = path[i]
            s2 = path[i+1]
            e1 = self.adjacency[s1][s2]
            self.queue_config.setdefault(e1,[])
            e1_name = self.sw_port[s1][e1]

            self.queue_config[e1_name].append(request)
            
            # Install qos and queue in ovsdb of ovs
            self.configure_qos(e1_name)
            queue_id = len(self.queue_config[e1_name])-1
            self.request_table[self.request_id]['queue_bind'][e1_name] = queue_id
            
            
            # Install flow qos in ovs
            self.mod_qos_paths(s1,vni,src_ip,dst_ip,e1,queue_id,vm_traffic)
            
            # Install in OVNDB
            # self.install_ovn(self,queue_id,request)
            
        dst_p_name = self.sw_port[path[-1]][dst_port]
        self.queue_config.setdefault(dst_port,[])
        self.queue_config[dst_p_name].append(request)
        
        queue_id = len(self.queue_config[dst_p_name])-1
        self.configure_qos(dst_p_name)
        self.mod_qos_paths(path[-1],vni,src_ip,dst_ip,dst_port,queue_id,vm_traffic)
        self.request_table[self.request_id]['queue_bind'][dst_p_name] = queue_id
        self.change = True
        # Install in OVNDB
        # self.install_ovn(self,queue_id,request)
            
    def check_demand(self,path,vni,src_ip,dst_ip):
        check_req = True
        for accept_req in self.request_table.values():
            if accept_req['path'] != path:
                continue
            if accept_req['vni'] != vni:
                continue
            if accept_req['src_ip'] != src_ip:
                continue
            if accept_req['dst_ip'] != dst_ip:
                continue
    
            check_req = False
            
        return check_req
    
    def mod_request(self,port,queue_id,request_mod):
        db = libovsdb.OVSDBConnection(ovsdb_server, "Open_vSwitch")
        get_port = db.select(table = "Port",
                    columns = ['_uuid',"qos"],
                    where = [["name", "==", port]])
        port_qos = get_port[0]['qos']
        config = []

        if request_mod.get("min-rate"):
            min_rate_list = ['min_rate',request_mod["min-rate"]]
            config.append(min_rate_list)
        if request_mod.get("max-rate"):
            max_rate_list = ['max_rate',request_mod["max-rate"]]
            config.append(max_rate_list)

        self.logger.info("configure: %s",config)


        get_queue = db.select(table = "QoS",
                            columns = ['_uuid',"queues"],
                            where = [["_uuid", "==", ["uuid",port_qos]]])
        # print("select qos result: %s" %(json.dumps(get_queue, indent=4)))

        for queue in get_queue[0]['queues']:
            if queue[0] != queue_id:
                continue
            queue_uuid = queue[1][1]
            
            res = db.update(table = "Queue",
                            row = {"other_config": ['map',config]},
                            where = [["_uuid", "==", ["uuid",queue_uuid]]])
 
      

    def handle_request_mod(self,request_id,request_mod):
        resp = "Success modify"
        cond = True
        if not request_mod.get("min-rate") and not request_mod.get("max-rate"):
            return "Wrong rate request", False
        self.logger.info("Request_table: %s",request_id)
        for port,queue_id in request_id['queue_bind'].items():
            self.mod_request(port,queue_id,request_mod)
            
        
                    
        return resp,cond
    
          # src_ip = request_id['src_ip']
        # dst_ip = request_id['dst_ip']
        # path = request_id['path']
        # vni = request_id['vni']
        # min_rate = request_id['request'].get('min-rate')
        # max_rate = request_id['request'].get('max-rate')
        # src = path[0]
        # dst = path[-1]
        # mac_src = self.arp_table[src_ip]
        # mac_dst = self.arp_table[dst_ip]
        # h1 = self.hosts[mac_src]
        # h2 = self.hosts[mac_dst]
        # dst_port = h2[2]


    def handle_request(self,request,path,src_ip,dst_ip,vni,vm_traffic):
        self.logger.info("RES: %s"%request)
        req_num = 1
        if vni and not vm_traffic:
            req_num = len(self.vni_map_hv[src_ip][int(vni)])*len(self.vni_map_hv[src_ip][int(vni)])
        
        if not request.get('max-rate') and not request.get('min-rate'):
            resp = "Wrong rate request"
            self.logger.info(resp)
            return resp, False
        
        if not path:
            resp = "Wrong path request"
            self.logger.info(resp)
            return resp, False
        
        src = path[0]
        dst = path[-1]
        if src_ip not in self.arp_table.keys():
            resp = "Host IP not found: %s" % src_ip
            self.logger.info(resp)
            return resp, False
        
        if dst_ip not in self.arp_table.keys():
            resp = "Host IP not found: %s" % dst_ip
            self.logger.info(resp)
            return resp, False
        
        
        mac_src = self.arp_table[src_ip]
        mac_dst = self.arp_table[dst_ip]
        
        h1 = self.hosts[mac_src]
        h2 = self.hosts[mac_dst]
        
        paths,pw = self.get_optimal_paths_qos(src, dst,h1[1],h2[1])
        self.logger.info("paths: %s\npw: %s" %(paths,pw))
        if path not in paths:
            resp = "Can`t find path: Path seem to be not correct"
            self.logger.info(resp)
            return resp, False
        
        
        if request.get('max-rate'):
            
            if int(request.get('max-rate'))*req_num > DEFAULT_BW:
                resp = "max-rate exceeds link bandwidth: \nThere are %d traffics bind to this demand" % req_num
                self.logger.info(resp)
                return resp, False
           
            if int(request.get('max-rate')) < 0 :
                resp = "request cant be negative"
                self.logger.info(resp)
                return resp, False
        
        
        if not request.get('min-rate'):
            check = self.check_demand(path,vni,src_ip,dst_ip)
            self.request_table.setdefault(self.request_id,{})
            self.request_table[self.request_id]={'request':request,'path':path,
                                                'vni':vni,'src_ip':src_ip,
                                                'dst_ip':dst_ip,'queue_bind':{}}
            
            if check == False:
                # Need to modify old queue/qos
                resp = "Request exist for the same type traffic"
                return resp, False
            
            
            self.accept_demand(request,path,h2[1],vni,src_ip,dst_ip,vm_traffic)   
            self.request_id += 1   
            resp = "Request accepted"  
            return resp, True

        if request.get('max-rate'):
            if int(request.get('min-rate')) > int(request.get('max-rate')):
                resp = "Invalid min request: Minrate > Maxrate"
                self.logger.info(resp)
                return resp, False
            
        if int(request.get('min-rate')) < 0 :
            resp = "request cant be negative"
            self.logger.info(resp)
            return resp, False
            
        index = 0
        min_rate = int(request.get('min-rate'))
        
        # Path was already found in the prev action
        for index in range(len(paths)):
            if paths[index] == path:  
                break
        self.logger.info("BAND:%s",pw)

        
        for avai_bw in pw[index]:
            if avai_bw <= min_rate*req_num:
                resp = "Reject: Minrate %s >= available bw: %s \
                \n(demand was bind to %s traffic)",min_rate,avai_bw,req_num
                self.logger.info(resp)
                return resp, False
       
        check = self.check_demand(path,vni,src_ip,dst_ip)
        if check == False:
            # Need to modify old queue/qos
            resp = "Request exist for the same type traffic"
            return resp, False
        
        for i in range(len(path)-1):
            s1 = path[i]
            s2 = path[i+1]
            e1 = self.adjacency[s1][s2]
            self.min_queue_config.setdefault(s1,{})
            self.min_queue_config[s1].setdefault(e1,0)
            self.min_queue_config[s1][e1]+=min_rate*req_num
            
        self.min_queue_config[path[-1]][h2[1]]+=min_rate*req_num
        
        self.request_table.setdefault(self.request_id,{})
        self.request_table[self.request_id]={'request':request,'path':path,
                                            'vni':vni,'src_ip':src_ip,
                                            'dst_ip':dst_ip,'queue_bind':{}}
        
        
        
            
        self.accept_demand(request,path,h2[1],vni,src_ip,dst_ip,vm_traffic)  
        self.request_id += 1    
        resp = "Request accepted"  
        return resp, True

                    
        # self.queue_config.append(request)
            
    def mod_paths(self,node,vni,src_ip,dst_ip,out_port):
        datapath = self.datapath_list[node]
        ofp = datapath.ofproto
        ofp_parser = datapath.ofproto_parser
        actions = [ofp_parser.OFPActionOutput(out_port)]
      
        # match = ofp_parser.OFPMatch(in_port=1, eth_dst='ff:ff:ff:ff:ff:ff')
        match_arp = ofp_parser.OFPMatch(
                        eth_type=0x0806, 
                        arp_spa=src_ip, 
                        arp_tpa=dst_ip
                    )
        
        match_icmp = ofp_parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=1,
                         
                        ipv4_src=src_ip, 
                        ipv4_dst=dst_ip,
                    )

        match_tcp = ofp_parser.OFPMatch(
                        eth_type=0x0800, 
                        ip_proto=6,
                        ipv4_src=src_ip, 
                        ipv4_dst=dst_ip
                    )
        
        match_udp = ofp_parser.OFPMatch(
                        eth_type=0x0800, 
                        ip_proto=17,
                        ipv4_src=src_ip, 
                        ipv4_dst=dst_ip
                    )
        
        if vni>0:
            match_vni = ofp_parser.OFPMatch(
                            eth_type=0x0800, 
                            ip_proto=17,
                            ipv4_src=src_ip, 
                            ipv4_dst=dst_ip,
                            udp_dst=6081,
                            tunnel_id = int(vni)
                            
                    )
            self.add_flow(datapath, 12, match_vni, actions,IDLE_TIMEOUT)
                    

        
        self.add_flow(datapath, 3, match_icmp, actions,IDLE_TIMEOUT)        
        
        self.add_flow(datapath, 10, match_tcp, actions,IDLE_TIMEOUT)
        self.add_flow(datapath, 10, match_udp, actions,IDLE_TIMEOUT)
        
                    
        self.add_flow(datapath, 1, match_arp , actions,IDLE_TIMEOUT)
        
    def accept_path(self,path,dst_port,vni,src_ip,dst_ip):
        for i in range(len(path)-1):
            s1 = path[i]
            s2 = path[i+1]
            e1 = self.adjacency[s1][s2]
            self.mod_paths(s1,vni,src_ip,dst_ip,e1)
            
        self.mod_paths(path[-1],vni,src_ip,dst_ip,dst_port)
        
    
    def handle_path(self,path,src_ip,dst_ip,vni):
        src = path[0]
        dst = path[-1]
        if src_ip not in self.arp_table.keys():
            self.logger.info("Host IP not found: %s", src_ip)
            resp = "Host IP not found: %s" % src_ip
            return resp, False
        
        if dst_ip not in self.arp_table.keys():
            self.logger.info("Host IP not found: %s", dst_ip)
            resp = "Host IP not found: %s" % dst_ip
            return resp, False
        
        
        mac_src = self.arp_table[src_ip]
        mac_dst = self.arp_table[dst_ip]
        
        h1 = self.hosts[mac_src]
        h2 = self.hosts[mac_dst]
        
        dst_port = h2[1]
        paths,pw = self.get_optimal_paths_qos(src, dst,h1[1],h2[1])
        self.logger.info("paths: %s\npw: %s" %(paths,pw))
        if path not in paths:
            self.logger.info("Can`t find path: Path seem to be not correct")
            resp = "Can`t find path: Path seem to be not correct"
            return resp, False     
        self.accept_path(path,dst_port,vni,src_ip,dst_ip)
        resp = "Path accepted"
        return resp, True
      
            
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        dpid = ev.msg.datapath.id
        body = ev.msg.body
        
        # if dpid == 1:
            # self.logger.info('datapath         port     '
            #                     'rx-pkts  rx-bytes rx-error '
            #                     'tx-pkts  tx-bytes tx-error')
            # self.logger.info('---------------- -------- '
            #                 '-------- -------- -------- '
            #                 '-------- -------- --------')
        # if dpid == 1:
        #     self.logger.info('datapath         port     tx-pkts  tx-bytes')
        #     self.logger.info('---------------- -------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            
            if(stat.port_no != 4294967294):
                # if dpid == 1:
                    
                #     self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                #                     ev.msg.datapath.id, stat.port_no,
                #                     stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                #                     stat.tx_packets, stat.tx_bytes, stat.tx_errors)

                port_no = stat.port_no
                self.tx_pkt_cur.setdefault(dpid, {})
                self.tx_byte_cur.setdefault(dpid, {})
                self.tx_pkt_int.setdefault(dpid, {})
                self.tx_byte_int.setdefault(dpid, {})
                
                self.rx_pkt_cur.setdefault(dpid, {})
                self.rx_byte_cur.setdefault(dpid, {})
                self.rx_pkt_int.setdefault(dpid, {})
                self.rx_byte_int.setdefault(dpid, {})                

                if port_no in self.tx_pkt_cur[dpid]:
                    self.rx_pkt_int[dpid][port_no] = stat.tx_packets - self.tx_pkt_cur[dpid][port_no]
                    if self.rx_pkt_int[dpid][port_no] < 0:
                        self.logger.warning('Negative value of interval TX packets')
                self.tx_pkt_cur[dpid][port_no] = stat.tx_packets

                if port_no in self.tx_byte_cur[dpid]:
                    self.tx_byte_int[dpid][port_no] = stat.tx_bytes - self.tx_byte_cur[dpid][port_no]
                    if self.tx_byte_int[dpid][port_no] < 0:
                        self.logger.warning('Negative value of interval TX bytes')
                self.tx_byte_cur[dpid][port_no] = stat.tx_bytes
                
                
                
                if port_no in self.rx_pkt_cur[dpid]:
                    self.rx_pkt_int[dpid][port_no] = stat.rx_packets - self.rx_pkt_cur[dpid][port_no]
                    if self.rx_pkt_int[dpid][port_no] < 0:
                        self.logger.warning('Negative value of interval RX packets')
                self.rx_pkt_cur[dpid][port_no] = stat.rx_packets

                if port_no in self.rx_byte_cur[dpid]:
                    self.rx_byte_int[dpid][port_no] = stat.rx_bytes - self.rx_byte_cur[dpid][port_no]
                    if self.rx_byte_int[dpid][port_no] < 0:
                        self.logger.warning('Negative value of interval RX bytes')
                self.rx_byte_cur[dpid][port_no] = stat.rx_bytes
                
                # if dpid == 1:
                #     if port_no in self.tx_pkt_int[dpid] and port_no in self.tx_byte_int[dpid]:
                #         self.logger.info('%016x %8x %8d', dpid, port_no,
                #                         # self.tx_pkt_int[dpid][port_no],
                #                         self.tx_byte_int[dpid][port_no])
                
            else:
                pass
     
        
        # self.banwidth_calculation(dpid)
        
        # self.logger.info("ARP: %s",self.arp_table)
        # self.FLAG = 1
        if dpid == 1 and self.change == True:
            self.logger.info("Table:%s", self.request_table)
            self.change = False


            
        # if self.FLAG > 50:
         

        #     # self.logger.info("RESERVE BW: %s"%self.sw_reserve_bw)
        #     self.logger.info("Sw RESERVE BW: %s"%self.sw_reserve_bw)       
        #     self.logger.info("Port RESERVE BW: %s"%self.port_reserve_bw)
            
              
    def replace_path(self,src,dst,p,pw):
        #1 switch connect to multiple host -> multiple IPs
        #return dict of IP:host
        src_ips = self.get_ip_from_dpid(src)
        dst_ips = self.get_ip_from_dpid(dst)
        ip_h1 = []
        ip_h2 = []
        p_reverse = []
        for i in p:
            # self.logger.info("PATH %s",i[::-1])
            #Reverse path for add flow
            p_reverse.append(i[::-1])

        for ip_host in src_ips:
            ip_h1.append(ip_host.popitem())
            
        for ip_host in dst_ips:
            ip_h2.append(ip_host.popitem())
        
        for ip_1,h_1 in ip_h1: 
            for ip_2,h_2 in ip_h2:
                self.install_replace_paths(src,self.hosts[h_1][1],dst,self.hosts[h_2][1],ip_1,ip_2,p,pw)              
                self.install_replace_paths(dst,self.hosts[h_2][1],src,self.hosts[h_1][1],ip_2,ip_1,p_reverse,pw)
     
    def get_host_from_dpid(self,dpid):
        return [k for k, v in self.hosts.items() if v[0] == dpid]
    
    def get_ip_from_dpid(self,dpid):
        hosts = self.get_host_from_dpid(dpid)
        ip = []
        for host in hosts:
            
            a = [{k:v} for k, v in self.arp_table.items() if v == host]
            # 1 host has only 1 IP
            ip.append(a[0])
        return ip     
    
    def get_ip_from_host(self,host):
        return [k for k, v in self.arp_table.items() if v == host]
    
    
    @set_ev_cls(ofp_event.EventOFPPortStatus, MAIN_DISPATCHER)
    def port_status_handler(self, ev):
        msg = ev.msg
        dp = msg.datapath
        ofp = dp.ofproto

        if msg.reason == ofp.OFPPR_ADD:
            reason = 'ADD'
        elif msg.reason == ofp.OFPPR_DELETE:
            reason = 'DELETE'
            
        elif msg.reason == ofp.OFPPR_MODIFY:
            reason = 'MODIFY'
            
        else:
            reason = 'unknown'
            
        # port = msg.desc.port_no

        port_attr = msg.desc
        
        self.logger.info('OFPPortStatus received: reason=%s desc=%s' ,
                          reason, msg.desc)
        
        
        
    # Port information:
        # self.logger.info("\t ***switch dpid=%s"
        #                  "\n \t port_no=%d hw_addr=%s name=%s config=0x%08x "
        #                  "\n \t state=0x%08x curr=0x%08x advertised=0x%08x "
        #                  "\n \t supported=0x%08x peer=0x%08x curr_speed=%d max_speed=%d" %
        #                  (dp.id, port_attr.port_no, port_attr.hw_addr,
        #                   port_attr.name, port_attr.config,
        #                   port_attr.state, port_attr.curr, port_attr.advertised,
        #                   port_attr.supported, port_attr.peer, port_attr.curr_speed,
        #                   port_attr.max_speed))
        
        
        
        out_port = port_attr.port_no
        host_dist = False
        remove_host = []
        if port_attr.state == 1:
            for host in self.hosts:
                if out_port == self.hosts[host][1] and self.hosts[host][0] == dp.id:
                    host_dist = True
                    self.logger.info("Host %s disconnected: dpid:%d port:%d " % (host,self.hosts[host][0],self.hosts[host][1]))
                    # del self.hosts[host]
                    remove_host.append(host)
                    ip = self.get_ip(host)
                    del self.arp_table[ip]
                    # self.logger.info("arp %s  " % (self.hosts)
            if host_dist == False:
            
                #del port flow and group
                self.logger.info("Port sw-sw down")
                for i in self.datapath_list.keys():
                    # self.delete_flow(self.datapath_list[i],0)
                    self.logger.info("Reset Topo And ready to install path")
                    self.delete_group_mod(self.datapath_list[i])
       

                
                self.multipath_group_ids = {}
                self.group_id_count =0
                self.group_ids = []
                # self.arp_table = {}
                self.sw_port = {}
                # self.hosts = {}
                return
                #del flow and group ...    
            else:
                #del host flow and group
                for host in remove_host:
                    del self.hosts[host]
                for i in self.datapath_list.keys():
                    # self.delete_flow(self.datapath_list[i],0)
                    self.logger.info("Reset Topo And ready to install path")
                    self.delete_group_mod(self.datapath_list[i])
                    self.multipath_group_ids = {}
                    self.group_id_count =0
                    self.group_ids = []
                    # self.arp_table = {}
                    self.sw_port = {}
           
        elif port_attr.state == 0:
            pass  
        
        
    #   #EventOFPPortStatsReply  
    # @set_ev_cls(ofp_event.EventOFPPortStateChange, MAIN_DISPATCHER)
    # def port_modify_handler(self, ev):
    #     # dp = ev.dp
    #     # port_attr = ev.port
    #     dp = ev.datapath
        

    #     body = ev.reason
    #     port = ev.port_no
        
    #     self.logger.info("dpid: %d reason: %s port: %d"%(dp.id,body,port))      
            
        
    #get ip from arp table with host
    def get_ip(self,host):
        for ip in self.arp_table:
            if self.arp_table[ip] == host:
                return ip
                
        
    
    # Active only when LLDP packet received
    @set_ev_cls(event.EventLinkDelete, MAIN_DISPATCHER)
    def link_delete_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        # Exception handling if switch already deleted
        try:
            del self.adjacency[s1.dpid][s2.dpid]
            del self.adjacency[s2.dpid][s1.dpid]
        except KeyError:
            pass
