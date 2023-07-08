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
from ryu.lib.packet import udp,vxlan

from ryu.lib.packet import ether_types
from ryu.lib import dpid, mac, ip
from ryu.topology.api import get_switch, get_link
from ryu.app.wsgi import ControllerBase
from ryu.topology import event

from ryu.lib import dpid as dpid_lib
from collections import defaultdict
from operator import itemgetter, attrgetter, mul

from ryu.controller import dpset

from ryu.lib import hub
from ryu import utils



from ryu.ofproto import ofproto_parser  


import os
import random
import time
import logging


# Cisco Reference bandwidth = 1 Gbps
REFERENCE_BW = 10000000


DEFAULT_BW = 10000000


MAX_PATHS = 10


VERBOSE = 0
DEBUGING = 0
SHOW_PATH = 0





# logging.basicConfig(level = logging.INFO)

class ProjectController(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]


    def __init__(self, *args, **kwargs):
        super(ProjectController, self).__init__(*args, **kwargs)
        self.mac_to_port = {}
        self.LEARNING = 1
        self.FLAG = 1
        
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
        self.sw_port = {}
        self.count = 0
        self.path_install_cnt =0
        
        self.max_bw = {}
        self.curr_max_bw = {}
        
        self.all_path ={}
        self.count_path = []
        self.all_path_curr = {}
    
        
        self.curr_paths = {}
        self.rm_dup_cur_paths = {}
        self.change_paths = []
        self.new_pw = []
        
    

        
        self.curr_pw = {}
        self.curr_pw_all = {}
        self.curr_paths_all = {}
        
        self.vx_src_dst = {}

        # self.ew = 0
        
        
        
        if DEBUGING == 1:
            self.logger.setLevel(logging.DEBUG)
        else:
            self.logger.setLevel(logging.INFO)
            

        
        # monitor
        self.sleep = 2
        # self.datapaths = {}
        self.monitor_thread = hub.spawn(self._monitor)
        self.tx_pkt_cur = {}    # currently monitoring TX packets
        self.tx_byte_cur = {}   # currently monitoring TX bytes
        self.tx_pkt_int = {}    # TX packets in the last monitoring interval
        self.tx_byte_int = {}    # TX bytes in the last monitoring interval
    
        
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
        # print('------')
        # print(e1,e2)
        # print(not self.tx_byte_int[s1][e1] or not self.tx_byte_int[s2][e2])
        # bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
        
        
        if not self.tx_byte_int.setdefault(s1,{}) or not self.tx_byte_int.setdefault(s2,{}):
            # bl = min(self.bandwidths[s1][e1], self.bandwidths[s2][e2])
            bl = 0
            # pass
            
            # print(bl)
            
        else:
            # bl = min(self.tx_byte_int[s1][e1], self.tx_byte_int[s2][e2])
            bl = (self.tx_byte_int[s1][e1]+self.tx_byte_int[s2][e2])
            # bl = bl - (self.tx_byte_int[s1][e1]+self.tx_byte_int[s2][e2])
            
            # print(bl)
            
        # ew = REFERENCE_BW/bl
        
        ew = bl
        # print("linkcost",ew)
        return ew


    def get_path_cost(self, path):
        '''
        Get the path cost
        '''
        cost = 0
        for i in range(len(path) - 1):
            cost += self.get_link_cost(path[i], path[i+1])
        return cost

    def sorted_path(self,paths,pw):
        # sorted paths based on pw
        zip_list = zip(pw,paths)
        sorted_zip_list = sorted(zip_list)
        sorted_list = [e for _, e in sorted_zip_list]
       
        # self.logger.info("sorted:%s",
                    
        #                 sorted_list)
        return sorted_list
           
                        
                        
                        
                    
                
    def get_optimal_paths(self, src, dst):
        '''
        Get the n-most optimal paths according to MAX_PATHS
        '''
        paths = self.get_paths(src, dst)
        paths_count = len(paths) if len(
            paths) < MAX_PATHS else MAX_PATHS
        pw = []
        for path in paths:
            pw.append(self.get_path_cost(path))
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
    
    # def generate_openflow_gid(self,src,dst):
    #     '''
    #     Returns a random OpenFlow group id
    #     '''
    #     n = random.randint(0, 2**32)
    #     while n in self.group_ids:
    #         n = random.randint(0, 2**32)
    #     self.group_ids.append(n)
    #     return n


    def install_paths(self, src, first_port, dst, last_port, ip_src, ip_dst,ip_proto,vx_src,vx_dst,dst_port,src_ip,dst_ip,vni):
        # if SHOW_PATH == 1:
        #     self.path_install_cnt +=1
            # self.logger.info("installing path cnt: %d" % (self.path_install_cnt))
        self.LEARNING = 1
        computation_start = time.time()
        paths,pw = self.get_optimal_paths(src, dst)
        # self.logger.info("paths:%s\n"
        #                  "pw:%s\n"
        #                  ,paths,pw)
        
        self.curr_paths.setdefault(src,{})
        # self.old_paths.setdefault((src,dst),paths[0])
      
        
        
        self.curr_pw.setdefault(src,{})
        
   
  
        
        
        
        self.curr_paths[src].setdefault(dst,paths[0])
        self.curr_pw[src].setdefault(dst,pw[0])
        
        self.curr_paths[src][dst] = paths[0]
        # if pw[0] not in self.curr_pw[src][dst]:
        self.curr_pw[src][dst] = pw[0]
        
        
        self.curr_paths_all.setdefault(src,{})
        self.curr_pw_all.setdefault(src,{})
        self.curr_paths_all[src].setdefault(dst,paths[0])
        self.curr_pw_all[src].setdefault(dst,pw[0])
        
        self.curr_paths_all[src][dst] = paths
        # if pw[0] not in self.curr_pw[src][dst]:
        self.curr_pw_all[src][dst] = pw
        
        
        
        self.rm_dup_cur_paths.setdefault(src,{})
        self.rm_dup_cur_paths[src].setdefault(dst,0)
        if self.rm_dup_cur_paths[src][dst] != self.curr_paths[src][dst]:
            self.change_paths.append((src,dst,paths[0]))
            self.new_pw.append((src,dst,paths[0]))
            
            self.rm_dup_cur_paths[src][dst] = self.curr_paths[src][dst]
        
        # paths = paths[0]
        pw = pw[0]

        
        # pw = []
        # for path in paths:
        #     pw.append(self.get_path_cost(path))
        #     if VERBOSE == 1:
        #         print(path, "cost = ", pw[len(pw) - 1])
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
                # self.logger.info("VNI: %s"%vni)
                match_arp = ofp_parser.OFPMatch(
                        eth_type=0x0806, 
                        arp_spa=ip_src, 
                        arp_tpa=ip_dst
                    )
                if ip_proto == 1:
                # Ipv4
                    match_ip = ofp_parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=ip_proto,
                         
                        ipv4_src=ip_src, 
                        ipv4_dst=ip_dst,
                    )
                    # ARP
                    
                elif ip_proto == 6:
                    match_ip = ofp_parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=ip_proto,
                        ipv4_src=ip_src, 
                        ipv4_dst=ip_dst,
                        tcp_dst=dst_port

                        

                    )
                    # ARP
                    match_arp = ofp_parser.OFPMatch(
                        eth_type=0x0806, 
                        arp_spa=ip_src, 
                        arp_tpa=ip_dst
                    )
                    
                elif ip_proto == 17:
                    match_ip = ofp_parser.OFPMatch(
                        eth_type=0x0800, 
                        ip_proto=ip_proto,
                        
                        ipv4_src=ip_src, 
                        ipv4_dst=ip_dst,
                        udp_dst=dst_port,
                        
                        tunnel_id = vni
                    )
                    # ARP
                    match_arp = ofp_parser.OFPMatch(
                        eth_type=0x0806, 
                        arp_spa=ip_src, 
                        arp_tpa=ip_dst
                    )
                else:
                    
                    
                    match_ip = ofp_parser.OFPMatch(
                        eth_type=0x0800,
                        ip_proto=ip_proto,
                         
                        ipv4_src=ip_src, 
                        ipv4_dst=ip_dst,
                    )
                


                out_ports = ports[in_port]

                # print("_OUTPORT",ports)

             
                # dup_port = {}
                # for i in range(0,len(out_ports)-1):
                #     for j in range(i+1,len(out_ports)):
                #         if out_ports[i][0] == out_ports[j][0]:
                #             if out_ports[i][0] not in dup_port:
                #                 dup_port.setdefault(out_ports[i][0],out_ports[i][1]+out_ports[j][1])
                #             else:
                #                 dup_port[out_ports[i][0]]+=out_ports[j][1]
                                
                # # print("dup: ", dup_port)
                
                # del_port = out_ports.copy()
             
                # for i in dup_port.keys():
                #     a=0
                #     for j in range(len(del_port)):
                #         if i == del_port[j][0]:
                #             out_ports.pop(a)
                #             a = a - 1
                #         a = a+1
                #     del_port = out_ports.copy()
                            
                #     out_ports.append((i, dup_port[i]))
                # # print("pos",out_ports_1)
                # # print("postype",type(out_ports_1[0]))
                # # print("postype",type(out_ports_1[0][0]),type(out_ports_1[0][1]))
                # del del_port          
                                
                            
                    
                    
                if VERBOSE == 1:
                    print("\t\t-Outport",out_ports )
                group_new = False    
                if (src, dst) not in self.multipath_group_ids:
                        self.all_group_id.setdefault(src,{})
                        group_new = True
                        self.multipath_group_ids[
                            src, dst] = self.generate_openflow_gid(src,dst)
                        self.all_group_id[src].setdefault(self.multipath_group_ids[
                            src, dst], {})

     
                # elif len(out_ports) == 1:
                actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]

                if ip_proto == 1:
                    self.add_flow(dp, 2, match_ip, actions)
                    
                else:
                    
                    self.add_flow(dp, 10, match_ip, actions)
                self.add_flow(dp, 1, match_arp, actions)
        # print("Path installation finished in ", time.time() - computation_start )
        # print(paths_with_ports[0][src][1])
        return paths_with_ports[src][1]
    
    def install_paths_arp(self, src, first_port, dst, last_port, ip_src, ip_dst,ip_proto,vx_src,vx_dst,dst_port,src_ip,dst_ip,vni):
        # if SHOW_PATH == 1:
        #     self.path_install_cnt +=1
            # self.logger.info("installing path cnt: %d" % (self.path_install_cnt))
        self.LEARNING = 1
        computation_start = time.time()
        paths,pw = self.get_optimal_paths(src, dst)
        # self.logger.info("paths:%s\n"
        #                  "pw:%s\n"
        #                  ,paths,pw)
        
        self.curr_paths.setdefault(src,{})
    
 
        
        
        self.curr_pw.setdefault(src,{})
        
   
  
        
        
        
        self.curr_paths[src].setdefault(dst,paths[0])
        self.curr_pw[src].setdefault(dst,pw[0])
        
        self.curr_paths[src][dst] = paths[0]
        # if pw[0] not in self.curr_pw[src][dst]:
        self.curr_pw[src][dst] = pw[0]
        
        
        self.curr_paths_all.setdefault(src,{})
        self.curr_pw_all.setdefault(src,{})
        self.curr_paths_all[src].setdefault(dst,paths[0])
        self.curr_pw_all[src].setdefault(dst,pw[0])
        
        self.curr_paths_all[src][dst] = paths
        # if pw[0] not in self.curr_pw[src][dst]:
        self.curr_pw_all[src][dst] = pw
        
        
        
        self.rm_dup_cur_paths.setdefault(src,{})
        self.rm_dup_cur_paths[src].setdefault(dst,0)
        if self.rm_dup_cur_paths[src][dst] != self.curr_paths[src][dst]:
            self.change_paths.append((src,dst,paths[0]))
            self.new_pw.append((src,dst,paths[0]))
            
            self.rm_dup_cur_paths[src][dst] = self.curr_paths[src][dst]
        
        # paths = paths[0]
        pw = pw[0]

        
        # pw = []
        # for path in paths:
        #     pw.append(self.get_path_cost(path))
        #     if VERBOSE == 1:
        #         print(path, "cost = ", pw[len(pw) - 1])
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
                # self.logger.info("VNI: %s"%vni)
               
                match_ip = ofp_parser.OFPMatch(
                    eth_type=0x0800, 
                    ip_proto = 1,
                    ipv4_src=ip_src, 
                    ipv4_dst=ip_dst,
                )
                # ARP
                match_arp = ofp_parser.OFPMatch(
                    eth_type=0x0806, 
                    arp_spa=ip_src, 
                    arp_tpa=ip_dst
                )
                


                out_ports = ports[in_port]

                # print("_OUTPORT",ports)

             
                # dup_port = {}
                # for i in range(0,len(out_ports)-1):
                #     for j in range(i+1,len(out_ports)):
                #         if out_ports[i][0] == out_ports[j][0]:
                #             if out_ports[i][0] not in dup_port:
                #                 dup_port.setdefault(out_ports[i][0],out_ports[i][1]+out_ports[j][1])
                #             else:
                #                 dup_port[out_ports[i][0]]+=out_ports[j][1]
                                
                # # print("dup: ", dup_port)
                
                # del_port = out_ports.copy()
             
                # for i in dup_port.keys():
                #     a=0
                #     for j in range(len(del_port)):
                #         if i == del_port[j][0]:
                #             out_ports.pop(a)
                #             a = a - 1
                #         a = a+1
                #     del_port = out_ports.copy()
                            
                #     out_ports.append((i, dup_port[i]))
                # # print("pos",out_ports_1)
                # # print("postype",type(out_ports_1[0]))
                # # print("postype",type(out_ports_1[0][0]),type(out_ports_1[0][1]))
                # del del_port          
                                
                            
                    
                    
                if VERBOSE == 1:
                    print("\t\t-Outport",out_ports )
                group_new = False    
                if (src, dst) not in self.multipath_group_ids:
                        self.all_group_id.setdefault(src,{})
                        group_new = True
                        self.multipath_group_ids[
                            src, dst] = self.generate_openflow_gid(src,dst)
                        self.all_group_id[src].setdefault(self.multipath_group_ids[
                            src, dst], {})

     
                # elif len(out_ports) == 1:
                actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]


                self.add_flow(dp, 2, match_ip, actions)
                self.add_flow(dp, 1, match_arp, actions)
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
        self.curr_paths_all[src][dst] = paths
        # if pw[0] not in self.curr_pw[src][dst]:
        self.curr_pw_all[src][dst] = pw
        
        # if paths[0] not in self.curr_paths[src][dst]:
        self.curr_paths[src][dst] = paths[0]
        # if pw[0] not in self.curr_pw[src][dst]:
        self.curr_pw[src][dst] = pw[0]
        
        self.rm_dup_cur_paths.setdefault(src,{})
        self.rm_dup_cur_paths[src].setdefault(dst,0)

        if self.rm_dup_cur_paths[src][dst] != self.curr_paths[src][dst]:
            self.change_paths.append((src,dst,paths[0]))
            self.new_pw.append((src,dst,pw[0]))
            # if src == 1 or dst == 1:
            #     if paths[0] != self.old_paths[src,dst] :
            #         self.old_pw[src,dst][0] = self.old_pw[src,dst][1]
            #         self.old_pw[src,dst][1] = pw[0]
            self.rm_dup_cur_paths[src][dst] = self.curr_paths[src][dst]


        # self.logger.info('pw %s'% pw)
        # self.logger.info('all_path %s'% self.all_path)
        # self.logger.info('cal_pw %s'% cal_pw)
   
        # self.logger.info('\t all_path %s\n \tcost: %s'%(paths,pw))
        
        pw = pw[0]         
        
        # renew:    
        
        
        # pw = []
        # for path in paths:
        #     pw.append(self.get_path_cost(path))
        #     if VERBOSE == 1:
        #         print(path, "cost = ", pw[len(pw) - 1])
        # sum_of_pw = sum(pw) * 1.0
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
            # print("\tnode {}: ports{}".format(node,ports) ) 


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
                                
                            
                    
                    
                # if VERBOSE == 1:
                # print("\t\t-src: {},dst: {}".format(src, dst))
                # print("\t\t-march_ip: {} \nmatch_arp: {}".format(match_ip, match_arp))
                
                # print("\t\t-Outport",out_ports )
                
                # if (node, src, dst) not in self.multipath_group_ids:
                #         self.all_group_id.setdefault(src,{})
                #         self.multipath_group_ids[
                #             node, src, dst] = self.generate_openflow_gid(src,dst)
                #         self.all_group_id[src].setdefault(self.multipath_group_ids[
                #             node, src, dst], {})   

                        
                



            
                actions = [ofp_parser.OFPActionOutput(out_ports[0][0])]


                self.add_flow(dp, 32768, match_ip, actions)
                self.add_flow(dp, 1, match_arp, actions)
        return 

    


        
        
    def add_flow(self, datapath, priority, match, actions, buffer_id=None):
        # print "Adding flow ", match, actions
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS,
                                             actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath=datapath, buffer_id=buffer_id,
                                    priority=priority, match=match,
                                    instructions=inst)

        else:
            mod = parser.OFPFlowMod(datapath=datapath, priority=priority,
                                    match=match, instructions=inst)
        datapath.send_msg(mod)
    
    
    @set_ev_cls(ofp_event.EventOFPErrorMsg,
    [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    # def error_msg_handler(self, ev):
    #     msg = ev.msg
    #     # self.logger.info('OFPErrorMsg received: type=0x%02x code=0x%02x '
        # 'message=%s \n ,msg=%s',
        # msg.type, msg.code, hex_array(msg.data),msg)
    
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
        self.add_flow(datapath, 0, match, actions)



    @set_ev_cls(ofp_event.EventOFPPortDescStatsReply, MAIN_DISPATCHER)
    def port_desc_stats_reply_handler(self, ev):
        switch = ev.msg.datapath
        for p in ev.msg.body:
            self.bandwidths[switch.id][p.port_no] = p.curr_speed


    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # self.logger.info("PACKETIN %d" % (self.count))
        self.count += 1
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
        
        ethvx_src = 0
        ethvx_dst = 0
        
        vx_lan = 0
        src_port = 0
        dst_port = 0
        ip_proto = -1
        vni = -1
        if isinstance(ip_pkt, ipv4.ipv4):
            # print("IPIP")
            # load balancing based on traffic monitoring
            
            
            ip_proto = ip_pkt.proto
            # print("ip_pkt",ip_pkt)
            
            
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
                if dst_port == 4789 or dst_port == 8472:
             
                    # self.logger.info("UDP PKT: %s"%udp_pkt)
                    vxlan_pkt = pkt.get_protocol(vxlan.vxlan)
                    vni = vxlan_pkt.vni
                    
                    vx_lan = 1
                    payload_pkt = pkt[4:]
                    # payload_pkt = packet.Packet(payload_pkt)
                    
                    # pkt_payload = payload_pkt.get_protocol(ipv4.ipv4)
                    # self.logger.info("\tvxlan_pkt PKT: %s" % pkt)
                    
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


                    
                    
                    # self.logger.info("vxlan_pkt PKT: %s" % vxlan_pkt)
                    # self.logger.info("\tvxlan_pkt payload PKT: %s" % payload_pkt)
                    # self.logger.info("\tethernetvx src: %s\t ethernetvx dst: %s" % (ethvx_src,ethvx_dst))
                    # self.logger.info("\tipvx src: %s\t ipvx dst: %s" % (ipvx_src,ipvx_dst))
                    
                    # self.logger.info("\tpayload: %s" % (packet.Packet(payload_pkt[-1])))
                    
                    
                    
                else:
                    # self.logger.info("\n\tDIFF PKT:%s"%udp_pkt)
                    pass
        
        
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
                    print("Installing: Src:{}, Src in_port{}. Dst:{}, Dst in_port:{}, Src_ip:{}, Dst_ip:{}".format(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip,ethvx_src,ethvx_dst,dst_port))
                out_port = self.install_paths_arp(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip,ip_proto,ethvx_src,ethvx_dst,dst_port,src_ip, dst_ip, vni)
                self.install_paths_arp(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip,ip_proto,ethvx_dst,ethvx_src,dst_port,src_ip, dst_ip, vni) # reverse
            elif arp_pkt.opcode == arp.ARP_REQUEST:
                if dst_ip in self.arp_table:
                    # print("dst_ip found in arptable")
                    self.arp_table[src_ip] = src
                    dst_mac = self.arp_table[dst_ip]
                    h1 = self.hosts[src]
                    h2 = self.hosts[dst_mac]
                    out_port = self.install_paths_arp(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip,ip_proto,ethvx_src,ethvx_dst,dst_port,src_ip, dst_ip, vni)
                    self.install_paths_arp(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip,ip_proto,ethvx_dst,ethvx_src,dst_port,src_ip, dst_ip, vni) # reverse
            if VERBOSE == 1:
                print("--arptable",self.arp_table)
        # print pkt
        # else:
        #     # print("notARP",pkt)
        #     pass
        
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
                out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip,ip_proto,ethvx_src,ethvx_dst,dst_port,src_ip, dst_ip, vni)
                self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip,ip_proto,ethvx_dst,ethvx_src,dst_port,src_ip, dst_ip, vni) # reverse
         
            
        
        actions = [parser.OFPActionOutput(out_port)]


        data = None
        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data


        out = parser.OFPPacketOut(
            datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
            actions=actions, data=data)
        datapath.send_msg(out)
        self.LEARNING = 0
            

        # ip_pkt = pkt.get_protocol(ipv4.ipv4)
        # if isinstance(ip_pkt, ipv4.ipv4):
        #     # load balancing based on traffic monitoring
        #     h1 = self.hosts[src]
        #     h2 = self.hosts[dst]

        #     if VERBOSE == 1:
        #         print("Installing: Src:{}, Src in_port{}. Dst:{}, Dst in_port:{}, Src_ip:{}, Dst_ip:{}".format(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip))
        #         out_port = self.install_paths(h1[0], h1[1], h2[0], h2[1], src_ip, dst_ip)
        #         self.install_paths(h2[0], h2[1], h1[0], h1[1], dst_ip, src_ip) # reverse
        
        # actions = [parser.OFPActionOutput(out_port)]


        # data = None
        # if msg.buffer_id == ofproto.OFP_NO_BUFFER:
        #     data = msg.data


        # out = parser.OFPPacketOut(
        #     datapath=datapath, buffer_id=msg.buffer_id, in_port=in_port,
        #     actions=actions, data=data)
        # datapath.send_msg(out)
        

    @set_ev_cls(event.EventSwitchEnter)
    def switch_enter_handler(self, ev):
        switch = ev.switch.dp
        ofp_parser = switch.ofproto_parser
        if VERBOSE == 1:
            print("Switch In: ",switch.id)

        if switch.id not in self.switches:
            self.switches.append(switch.id)
            self.datapath_list[switch.id] = switch


            # Request port/link descriptions, useful for obtaining bandwidth
            req = ofp_parser.OFPPortDescStatsRequest(switch)
            switch.send_msg(req)


    @set_ev_cls(event.EventSwitchLeave, MAIN_DISPATCHER)
    def switch_leave_handler(self, ev):
        print(ev)
        switch = ev.switch.dp.id
        if switch in self.switches:
            self.switches.remove(switch)
            del self.datapath_list[switch]
            del self.adjacency[switch]


    @set_ev_cls(event.EventLinkAdd, MAIN_DISPATCHER)
    def link_add_handler(self, ev):
        s1 = ev.link.src
        s2 = ev.link.dst
        
        self.adjacency[s1.dpid][s2.dpid] = s1.port_no
        self.adjacency[s2.dpid][s1.dpid] = s2.port_no
        
        self.sw_port.setdefault(s1.dpid, [])
        self.sw_port.setdefault(s2.dpid, [])
        
        if s1.port_no not in self.sw_port[s1.dpid]:
            self.sw_port[s1.dpid].append(s1.port_no)
        if s2.port_no not in self.sw_port[s2.dpid]:
            self.sw_port[s2.dpid].append(s2.port_no)
        # print('----------------------------port',self.sw_port)
            

        
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

        # req = parser.OFPFlowStatsRequest(datapath)
        # datapath.send_msg(req)
        
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

        # for dst in self.all_group_id[datapath.id].keys():
        # self.logger.info("dpid:%s "
        #                             %(datapath.id))
        
        # self.logger.info("allgr:%s "
        #                             %(self.all_group_id))

        if not self.all_group_id or not self.all_group_id.setdefault(datapath.id,{}):
            return
        else:
            for group_id in self.all_group_id[datapath.id].keys():
                #buckets
        
                # self.logger.info("dataid:%d gID:%d" %(datapath.id,group_id))

                
                # group_id = ofp.OFPG_ALL to delete all group
                req = ofp_parser.OFPGroupMod(datapath, ofp.OFPGC_DELETE, 0, group_id)  
                datapath.send_msg(req)
            del self.all_group_id[datapath.id]
                


        
    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        # self.logger.info("PortStat")
        
        dpid = ev.msg.datapath.id
        body = ev.msg.body
        
        # if dpid == 1:
            # self.logger.info('datapath         port     '
            #                     'rx-pkts  rx-bytes rx-error '
            #                     'tx-pkts  tx-bytes tx-error')
            # self.logger.info('---------------- -------- '
            #                 '-------- -------- -------- '
            #                 '-------- -------- --------')
        if dpid == 1:
            self.logger.info('datapath         port     tx-pkts  tx-bytes')
            self.logger.info('---------------- -------- -------- --------')
        for stat in sorted(body, key=attrgetter('port_no')):
            
            if(stat.port_no != 4294967294):
                if dpid == 1:
                    
                    self.logger.info('%016x %8x %8d %8d %8d %8d %8d %8d',
                                    ev.msg.datapath.id, stat.port_no,
                                    stat.rx_packets, stat.rx_bytes, stat.rx_errors,
                                    stat.tx_packets, stat.tx_bytes, stat.tx_errors)

                port_no = stat.port_no
                self.tx_pkt_cur.setdefault(dpid, {})
                self.tx_byte_cur.setdefault(dpid, {})
                self.tx_pkt_int.setdefault(dpid, {})
                self.tx_byte_int.setdefault(dpid, {})
                self.curr_max_bw.setdefault(dpid, {})
                self.max_bw.setdefault(dpid, {})
                
                
                
                

                if port_no in self.tx_pkt_cur[dpid]:
                    self.tx_pkt_int[dpid][port_no] = stat.tx_packets - self.tx_pkt_cur[dpid][port_no]
                    if self.tx_pkt_int[dpid][port_no] < 0:
                        self.logger.warning('Negative value of interval TX packets')
                self.tx_pkt_cur[dpid][port_no] = stat.tx_packets

                if port_no in self.tx_byte_cur[dpid]:
                    self.tx_byte_int[dpid][port_no] = stat.tx_bytes - self.tx_byte_cur[dpid][port_no]
                    if self.tx_byte_int[dpid][port_no] < 0:
                        self.logger.warning('Negative value of interval TX bytes')
                self.tx_byte_cur[dpid][port_no] = stat.tx_bytes
                
                if dpid == 1:
                    if port_no in self.tx_pkt_int[dpid] and port_no in self.tx_byte_int[dpid]:
                        self.logger.info('%016x %8x %8d', dpid, port_no,
                                        # self.tx_pkt_int[dpid][port_no],
                                        self.tx_byte_int[dpid][port_no])
                
            else:
                pass
     
        # self.max_bw[dpid] = sorted(self.tx_byte_int[dpid].items(), key=lambda x: x[1], reverse=True)  
       
       
        self.curr_paths.setdefault(dpid,{})
        self.curr_pw.setdefault(dpid,{})
        
        self.FLAG = 1
        
        start = 20
        if self.FLAG == start:
            self.logger.info("FLAG START %s"% (self.FLAG))
        if self.FLAG > start:
            # self.logger.info("count_path %s"% (self.count_path))
            # if self.FLAG == 200:
                
            # self.count_path = []
            # self.all_path = self.all_path_curr
            # print('pop',self.all_path)
            
            # if dpid not in self.count_path:
            # self.count_path.append(dpid)
            
            # if self.LEARNING == 0:
                # self.logger.info("Calculating bw")
                
            for dst in self.switches:
                self.curr_paths[dpid].setdefault(dst,{})
                
                if dst == dpid:
                    continue
                else:
                    # if dpid==1 and dst == 3:
                    p,pw = self.get_optimal_paths(dpid,dst)
                    if self.curr_paths[dpid][dst] != p[0]:
                        self.logger.info("Reset weight") 
                        self.replace_path(dpid,dst,p,pw)
                            # self.FLAG = -50
                
    
        # Debug                #   
        if dpid == 1:
    
   
        #     p,pw = self.get_optimal_paths(1,3)
        #     self.logger.info("path 1-3 %s\n\tcost:%s"%(p,pw))
            if self.curr_paths[dpid]:
                self.logger.info('\t CURR_ %s\n \tcost: %s'%(self.curr_paths[dpid],self.curr_pw[dpid]))
            #             self.logger.info('\t ALL-CURR_paths %s\n \tall-cost: %s\n'%(self.curr_paths_all[dpid],self.curr_pw_all
                                                                                    # [dpid]))
                
                        
                       
#             # self.FLAG = 0 
#                     self.logger.info(
# "\t\t_____________________________RESETPATH_______________________________\n\n")
                                                                          
                
              
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
        # self.logger.info("PATH %s",p)
        # self.logger.info("PATH 1%s",p_reverse)
        
        for ip_host in src_ips:
            ip_h1.append(ip_host.popitem())
            
        for ip_host in dst_ips:
            ip_h2.append(ip_host.popitem())
        
        for ip_1,h_1 in ip_h1:
            # self.logger.info("HOST ip: %s host: %s"% (ip_1,h_1))   
            for ip_2,h_2 in ip_h2:
                # self.logger.info("HOST ip2: %s host2: %s"% (ip_2,h_2))  
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
                         
            
                           
            # DELETE OPTION:
                # multipath : (node in path, srcid, dstid)
                # del group id
                
                # multi_group = self.multipath_group_ids.copy()
                # for multipath in self.multipath_group_ids.keys():
                #     # print("multi",multipath)
                #     if not multipath:
                #         continue
                #     else:
                #         if dpid == multipath[1]:
                #             node = multipath[0]
                #             dst = multipath[2]
                #             if self.group_id_count > self.multipath_group_ids[node,dpid,dst]:
                #                 self.group_id_count = self.multipath_group_ids[node,dpid,dst] - 1
                #             self.group_ids.remove(self.multipath_group_ids[node,dpid,dst])
                #             del multi_group[node,dpid,dst]
                #             # self.logger.info("TRUEEEEEEEEEEEEEEEEEEEEEEEEEEEee")
                #         if dpid == multipath[2]:
                #             node = multipath[0]
                #             src = multipath[1]
                #             if self.group_id_count > self.multipath_group_ids[node,src,dpid]:
                #                 self.group_id_count = self.multipath_group_ids[node,src,dpid] - 1
                #             self.group_ids.remove(self.multipath_group_ids[node,src,dpid])
                #             del multi_group[node,src,dpid]
                            
                # self.multipath_group_ids = multi_group
                # self.delete_group_mod(self.datapath_list[dpid])
                
                
            # DELETE ALL OPTION
                # for i in self.datapath_list.keys():
                #     # self.delete_flow(self.datapath_list[i],0)
                #     # self.logger.info("Reset Topo And ready to install path")
                #     self.delete_group_mod(self.datapath_list[i])
   

                
                # self.multipath_group_ids = {}
                # self.group_id_count =0
                # self.group_ids = []
                # # self.arp_table = {}
                # self.sw_port = {}
                
        
    
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