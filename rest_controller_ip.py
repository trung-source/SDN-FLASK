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

simple_switch_instance_name = 'simple_switch_api_app'
url = '/simpleswitch/mactable/{dpid}'
switch_url = '/simpleswitch/switch/{dpid}'
vni_url = '/simpleswitch/vni/'
request_url = '/simpleswitch/request/'
path_url = '/simpleswitch/path/'


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
    
    
    def get_switch(self,node=None):
        if node:
            tmp = int(node)
            if tmp not in self.switches:
                return "Cant find switch %s. All switches: %s" % (node,self.switches)
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
            return resp
        
        return self.switches
            
            
    def set_vni(self, entry):
        self.vni= entry['vni'] 
        return self.vni
    
    def set_request(self, entry):
        # self.logger.info("ITS GO IN HERE")
        resp = ""
        DO_SET_REQUEST = True
        for id in self.request_table:
            if self.request_table[id]['vni'] != entry["vni"]:
                continue
            
            if self.request_table[id]['path'] != entry["path"]:
                continue
            
            if self.request_table[id]['request'] != entry["request"]:
                continue
            
            if self.request_table[id]['src_ip'] != entry["src_ip"]:
                continue
            
            if self.request_table[id]['dst_ip'] != entry["dst_ip"]:
                continue
            DO_SET_REQUEST = False
            
            
        
        if DO_SET_REQUEST:
            # self.request_table.setdefault(self.request_id,{})
            # self.request_table[self.request_id]={'request':entry['request'],'path':entry['path'],
            #                                     'vni':entry['vni'],'src_ip':entry['src_ip'],
            #                                     'dst_ip':entry['dst_ip'],}
            # self.request_id += 1
            self.logger.info("New Request")
            resp = self.handle_request(entry['request'],entry['path'],entry['src_ip'],entry['dst_ip'],entry['vni'])
        else:
            self.logger.info("Duplicate Request")
            resp = "Duplicate Request"
        
        # self.logger.info("DONE MAP")
        
        return resp
    
    
    def set_path(self, entry):
        # self.logger.info("ITS GO IN HERE")
        resp = ""
        resp = self.handle_path(entry['path'],entry['src_ip'],entry['dst_ip'],entry['vni'])
       
        # self.logger.info("DONE MAP")
        
        return resp


    def set_mac_to_port(self, dpid, entry):
        mac_table = self.mac_to_port.setdefault(dpid, {})
        datapath = self.switches.get(dpid)

        entry_port = entry['vni']
        entry_mac = entry['mac']

        if datapath is not None:
            parser = datapath.ofproto_parser
            if entry_port not in mac_table.values():

                for mac, port in mac_table.items():

                    # from known device to new device
                    actions = [parser.OFPActionOutput(entry_port)]
                    match = parser.OFPMatch(in_port=port, eth_dst=entry_mac)
                    self.add_flow(datapath, 1, match, actions)

                    # from new device to known device
                    actions = [parser.OFPActionOutput(port)]
                    match = parser.OFPMatch(in_port=entry_port, eth_dst=mac)
                    self.add_flow(datapath, 1, match, actions)

                mac_table.update({entry_mac: entry_port})
        return mac_table


class SimpleSwitchController(ControllerBase):

    def __init__(self, req, link, data, **config):
        super(SimpleSwitchController, self).__init__(req, link, data, **config)
        self.simple_switch_app = data[simple_switch_instance_name]

    @route('simpleswitch', url, methods=['GET'],
           requirements={'dpid': dpid_lib.DPID_PATTERN})
    def list_mac_table(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        dpid = kwargs['dpid']

        if dpid not in simple_switch.mac_to_port:
            return Response(status=404)

        mac_table = simple_switch.mac_to_port.get(dpid, {})
        body = json.dumps(mac_table)
        return Response(content_type='application/json', text=body)

        
    
    @route('simpleswitch', switch_url, methods=['GET'])
    def list_switches(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        dpid = kwargs['dpid']

        get_switch = simple_switch.get_switch(dpid)
        body = json.dumps(get_switch)
        return Response(content_type='application/json', text=body)
    
    
    
    @route('simpleswitch', vni_url, methods=['PUT'])
    def put_vni(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        try:
            mac_table = simple_switch.set_vni(new_entry)
            body = json.dumps(mac_table)
            return Response(content_type='application/json', text=body)
        except Exception as e:
            return Response(status=500)
        
        
        
    @route('simpleswitch', request_url, methods=['PUT'])
    def put_request(self, req, **kwargs):

        simple_switch = self.simple_switch_app
        try:
            new_entry = req.json if req.body else {}
        except ValueError:
            raise Response(status=400)

        # try:
        resp = simple_switch.set_request(new_entry)
        
        body = json.dumps(resp)
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
            resp = simple_switch.set_path(new_entry)
            
            body = json.dumps(resp)
            return Response(content_type='application/json', text=body)
        except Exception as e:
                return Response(status=500)
            
            
    # @route('simpleswitch', path_url, methods=['GET'])
    # def list_request(self, req, **kwargs):

    #     simple_switch = self.simple_switch_app


    #     vni = simple_switch.vni
    #     body = json.dumps(vni)
    #     return Response(content_type='application/json', text=body)