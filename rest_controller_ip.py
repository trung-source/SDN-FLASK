# Copyright (C) 2016 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

import json

import Controller_IP
from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import set_ev_cls
from ryu.app.wsgi import ControllerBase
from ryu.app.wsgi import Response
from ryu.app.wsgi import route
from ryu.app.wsgi import WSGIApplication
from ryu.lib import dpid as dpid_lib
from libovsdb import libovsdb
import re

simple_switch_instance_name = 'simple_switch_api_app'

all_switch_url = '/simpleswitch/allswitch/'
switch_url = '/simpleswitch/switch/{dpid}'
vni_url = '/simpleswitch/vni/'
request_url = '/simpleswitch/request/'
path_url = '/simpleswitch/path/'
path_find_url = '/simpleswitch/pathfind/'
host_url = '/simpleswitch/host/'

virtual_topo_url = '/simpleswitch/virtualtopo/'


ovn_nb = 'tcp:192.168.15.165:6641'
ovn_sb = 'tcp:192.168.15.165:6642'

class SimpleSwitchRest13(Controller_IP.ProjectController):

    _CONTEXTS = {'wsgi': WSGIApplication}

    def __init__(self, *args, **kwargs):
        super(SimpleSwitchRest13, self).__init__(*args, **kwargs)
        # self.switches = {}
        wsgi = kwargs['wsgi']
        wsgi.register(SimpleSwitchController,
                      {simple_switch_instance_name: self})

    # @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    # def switch_features_handler(self, ev):
    #     super(SimpleSwitchRest13, self).switch_features_handler(ev)
    #     datapath = ev.msg.datapath
    #     self.switches[datapath.id] = datapath
    #     self.mac_to_port.setdefault(datapath.id, {})
    
    def get_virtual_topo(self):
            lswitchs = {}
            encaps = []
            chassises = []
            sb = libovsdb.OVSDBConnection(ovn_sb, "OVN_Southbound")
            # nb = libovsdb.OVSDBConnection(ovn_nb, "OVN_Northbound")

            # tx_nb = nb.transact()
            tx_sb = sb.transact()

            # Get logical switch uuid and vni from sb
            res = tx_sb.row_select(table = "Datapath_Binding",
                        columns = ["_uuid","tunnel_key"],
                        where = [])
            res = tx_sb.row_select(table = "Chassis",
                        columns = ["_uuid","encaps"],
                        where = [])
            res = tx_sb.row_select(table = "Encap",
                        columns = ["_uuid","ip"],
                        where = [])
            try:
                response = tx_sb.commit()
                lss = response['result'][0]['rows']

                chassises = response['result'][1]['rows']
                for chassis in chassises:
                    chassis['_uuid'] = chassis['_uuid'][1]
                    chassis['encaps'] = chassis['encaps'][1]

                encaps = response['result'][2]['rows']
                for encap in encaps:
                    encap['_uuid'] = encap['_uuid'][1]
            except:
                return response, False
            else:
                for ls in lss:
                    attr = {}
                    attr['vni'] = ls.get('tunnel_key')
                    attr['ports'] = []
                    uuid = ls.get('_uuid')[1]

                    response = tx_sb.row_select(table = "Port_Binding",
                                        columns = ['mac','tunnel_key','chassis'],
                                        where = [["datapath", "==", ["uuid",uuid]]])
                    try :
                        res = tx_sb.commit()
                        lps = res['result'][0]['rows']
                        lports = []
                        for lp in lps:
                            temp = {'inner_ip': '', 'outter_ip': '', 'tunnel_key': ''}
                            for chassis in chassises:
                                if chassis['_uuid'] == lp.get('chassis')[1]:
                                    for encap in encaps:
                                        if encap['_uuid'] == chassis['encaps']:
                                            temp['outter_ip'] = encap['ip']

                            temp['inner_ip'] = re.findall( r'[0-9]+(?:\.[0-9]+){3}', lp.get('mac'))[0]
                            temp['tunnel_key'] = int(lp.get('tunnel_key'))
                            lports.append(temp)
                    except:
                        return response,False
                    else:
                        attr['ports'] = lports
                        lswitchs[ls.get('_uuid')[1]] = attr
            result = list(lswitchs.values())
            return result, True

    def get_switch_all(self):    
        resp = {}
        sw_list = sorted(self.switches)
        port_list = []
        for sw in sw_list:
            port_list.append(list(self.sw_port[sw].values()))
        self.logger.info("sw_list: %s\nport_list: %s"%(sw_list,port_list))
        resp["sw_list"] = sw_list
        resp["port_list"] = port_list
        return resp, True
        
    def get_switch(self,node=None):
        if node:
            tmp = int(node)
            if tmp not in self.switches:
                resp = "Cant find switch %s. All switches: %s" % (node,sorted(self.switches))
                return resp , False
            resp = {}
            # datapath = list(self.datapath_list[tmp])
            adjacency = list(self.adjacency[tmp].keys())
            port = list(self.sw_port[tmp].values())
            host = self.get_host_from_dpid(tmp)
            
            resp[node] = {
                            # 'datapath':datapath,
                            'adjacency_switches':adjacency,
                             'port':port,
                             'host':host            
                          }
            self.logger.info("RESP: %s" % resp)
            return resp , True
        
        return sorted(self.switches), True
    
    def get_host(self):
        resp = {}
        resp['host'] = []
        resp['dpid'] = []
        resp['inport'] = []
        resp['ip'] = []
        for host in self.hosts.keys():
            resp['host'].append(host)
            sw = self.hosts[host][0]
            port = self.hosts[host][1]
            port_name = self.sw_port[sw][port]
            ip = self.get_ip_from_host(host)
            
            resp['dpid'].append(sw)   
            resp['inport'].append(port_name)
            resp['ip'].append(ip)
            
        self.logger.info("RESP:%s"%resp)
        
        return resp, True
        
            
  
    def set_request(self, entry):
        # self.logger.info("ITS GO IN HERE")
        resp = ""
        cond = False
        DO_SET_REQUEST = True
        DO_MOD = False
        for id in self.request_table:
            if self.request_table[id]['vni'] != entry["vni"]:
                continue
            
            if self.request_table[id]['path'] != entry["path"]:
                continue
            
            
            
            if self.request_table[id]['src_ip'] != entry["src_ip"]:
                continue
            
            if self.request_table[id]['dst_ip'] != entry["dst_ip"]:
                continue

            if self.request_table[id]['request'] == entry["request"]:
                return "Duplicate request", False
            

            if "mod" not in list(entry.keys()) or not entry["mod"]:
                resp = "Duplicate request (Not a modding request): %s/ %s" %(entry.keys(),entry["mod"])
                return resp , False
            
            


            DO_SET_REQUEST = False

            self.logger.info("Mod Request")
            resp,cond = self.handle_request_mod(self.request_table[id],entry["request"])
            if cond == True:
                self.request_table[id]['request']  = entry["request"]
            break
            
            
            
        
        if DO_SET_REQUEST:
            # self.request_table.setdefault(self.request_id,{})
            # self.request_table[self.request_id]={'request':entry['request'],'path':entry['path'],
            #                                     'vni':entry['vni'],'src_ip':entry['src_ip'],
            #                                     'dst_ip':entry['dst_ip'],}
            # self.request_id += 1
            self.logger.info("New Request")
            resp,cond = self.handle_request(entry['request'],entry['path'],entry['src_ip'],entry['dst_ip'],entry['vni'])
        
        
      
            
        
        # self.logger.info("DONE MAP")
        
        return resp, cond
    
    
    def set_path(self, entry):
        # self.logger.info("ITS GO IN HERE")
        resp,cond = self.handle_path(entry['path'],entry['src_ip'],entry['dst_ip'],entry['vni'])
       
        # self.logger.info("DONE MAP")
        
        return resp,cond

    def set_path_find(self, entry):
        # self.logger.info("ITS GO IN HERE")
        src_ip = entry['src_ip']
        dst_ip = entry['dst_ip']
        if src_ip not in self.arp_table.keys():
            return "Can`t find source IP:", False
        if dst_ip not in self.arp_table.keys():
            return "Can`t find destination IP", False
        mac_src = self.arp_table[src_ip]
        mac_dst = self.arp_table[dst_ip]
        
        h1 = self.hosts[mac_src]
        h2 = self.hosts[mac_dst]
        paths,pw = self.get_optimal_paths_qos(h1[0], h2[0],h1[1],h2[1])
        resp = {}
        resp['paths'] = paths
        resp['pw'] = pw
        # self.logger.info("DONE paths:%s\npw:%s"%(paths,pw))
        
        return resp, True


class SimpleSwitchController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(SimpleSwitchController, self).__init__(req, link, data, **config)
        self.simple_switch_app = data[simple_switch_instance_name]


    @route('simpleswitch', virtual_topo_url, methods=['GET'])
    def list_virtual_topo(self, req, **kwargs):

        simple_switch = self.simple_switch_app

        virtual_topo,cond = simple_switch.get_virtual_topo()
        body = json.dumps(virtual_topo)
        if cond == True:
            return Response(content_type='application/json', text=body)
        return Response(status=500,content_type='application/json', text=body)
    
    @route('simpleswitch', all_switch_url, methods=['GET'])
    def list_switches_all(self, req, **kwargs):

        simple_switch = self.simple_switch_app

        get_switch,cond = simple_switch.get_switch_all()
        body = json.dumps(get_switch)
        if cond == True:
            return Response(content_type='application/json', text=body)
        return Response(status=500,content_type='application/json', text=body)
    
    @route('simpleswitch', switch_url, methods=['GET'])
    def list_switches(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        dpid = kwargs['dpid']

        get_switch,cond = simple_switch.get_switch(dpid)
        body = json.dumps(get_switch)
        if cond == True:
            return Response(content_type='application/json', text=body)
        return Response(status=500,content_type='application/json', text=body)
    
    @route('simpleswitch', host_url, methods=['GET'])
    def list_host(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        # dpid = kwargs['dpid']

        get_host,cond = simple_switch.get_host()
        body = json.dumps(get_host)
        if cond == True:
            return Response(content_type='application/json', text=body)
        return Response(status=500,content_type='application/json', text=body)
    
        
    @route('simpleswitch', request_url, methods=['PUT'])
    def put_request(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        # try:
        resp,cond = simple_switch.set_request(new_entry)
        
        body = json.dumps(resp)
        if cond == False:
            return Response(status=500,content_type='application/json', text=body)
        return Response(content_type='application/json', text=body)
        # except Exception as e:
        #         return Response(status=500)

    
    @route('simpleswitch', path_url, methods=['PUT'])
    def put_path(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        try:
            resp,cond = simple_switch.set_path(new_entry)
            
            body = json.dumps(resp)
            if cond == False:
                return Response(status=500,content_type='application/json', text=body)
            return Response(content_type='application/json', text=body)
        except Exception as e:
                return Response(status=500)
            
    @route('simpleswitch', path_find_url, methods=['PUT'])
    def put_path_find(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        try:
            resp,cond = simple_switch.set_path_find(new_entry)
            body = json.dumps(resp)
            if cond == False:
                return Response(status=500,content_type='application/json', text=body)
            return Response(content_type='application/json', text=body)
        except Exception as e:
                return Response(status=500)
                   
    # @route('simpleswitch', path_url, methods=['GET'])
    # def list_request(self, req, **kwargs):

    #     simple_switch = self.simple_switch_app


    #     vni = simple_switch.vni
    #     body = json.dumps(vni)
    #     return Response(content_type='application/json', text=body)
