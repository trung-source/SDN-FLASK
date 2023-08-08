import requests
import json
from libovsdb import libovsdb
import re
ryu_ip = 'http://127.0.0.1:8081'
ovn_nb = 'tcp:192.168.122.230:6641'
ovn_sb = 'tcp:192.168.122.230:6642'

switch_all_url = ryu_ip +'/simpleswitch/allswitch/'
switch_url = ryu_ip +'/simpleswitch/switch/'
request_url = ryu_ip + '/simpleswitch/request/'
path_find_url = ryu_ip + '/simpleswitch/pathfind/'

host_url = ryu_ip +'/simpleswitch/host/'

# DEFAULT_OVN_BW = "1,000,000,000"
# DEFAULT_OVN_BW = DEFAULT_OVN_BW.replace(",", "")
# DEFAULT_OVN_BW = int(DEFAULT_OVN_BW)
# HFSC take almost 0.95 of link BW
DEFAULT_OVN_BW = 1000000000
DEFAULT_OVN_BW = 100000000

# DEFAULT_OVN_BW = int(1000000000/0.97)
QUEUE_TYPE = 'linux-hfsc'

def get_virtual_topo():
    lswitch = {}
    encaps = []
    chassises = []
    sb = libovsdb.OVSDBConnection(ovn_sb, "OVN_Southbound")
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
    except Exception as msg:
        raise ValueError(msg)
    else:
        for ls in lss:
            attr = {}
            attr['vni'] = ls.get('tunnel_key')
            attr['ports'] = []
            uuid = ls.get('_uuid')[1]

            response = tx_sb.row_select(table = "Port_Binding",
                                columns = ['mac','tunnel_key','chassis','logical_port'],
                                where = [["datapath", "==", ["uuid",uuid]]])
            # try :
            res = tx_sb.commit()
            lps = res['result'][0]['rows']
            # print(lps)
            lports = []
            for lp in lps:
                temp = {'inner_ip': '', 'outter_ip': '', 'tunnel_key': '','logical_port': ''}
                for chassis in chassises:
                    if chassis['_uuid'] != lp.get('chassis')[1]:
                        continue
                    for encap in encaps:
                        if encap['_uuid'] == chassis['encaps']:
                            temp['outter_ip'] = encap['ip']

                temp['inner_ip'] = re.findall( r'[0-9]+(?:\.[0-9]+){3}', lp.get('mac'))
                temp['tunnel_key'] = int(lp.get('tunnel_key'))
                temp['logical_port'] = (lp.get('logical_port'))

                lports.append(temp)
            # except Exception as msg:
            #     raise ValueError(msg)
            else:
                attr['ports'] = lports
                lswitch[ls.get('_uuid')[1]] = attr  
    result = list(lswitch.values())
    return result

def get_switch_all():
    url = switch_all_url
    x = requests.get(url)
    return x
    

def get_switch(switch_id):
    url = switch_url + str(switch_id)
    x = requests.get(url)
    return x


def get_host():
    url = host_url 
    x = requests.get(url)
    return x

def get_bw_ovn_all(virtual_topo):
    db = libovsdb.OVSDBConnection(ovn_nb, "OVN_Northbound")
    vm_ip_dict = {}
    for ls in virtual_topo:
        vni = ls["vni"]
        lsps = ls["ports"]
        for lsp in lsps:
            if not lsp["outter_ip"]:
                continue
            vm_ip_dict[lsp["outter_ip"]]=(lsp["inner_ip"][0],lsp['logical_port'],vni)
            # vm_ip_dict[lsp["inner_ip"][0]]=(lsp["outter_ip"],lsp['logical_port'],vni)

    # print(vm_ip_dict)
    bw_min_list = {}
    for ip in vm_ip_dict.keys():
        port = vm_ip_dict[ip][1]
        res = db.select(table = "Logical_Switch_Port",
            columns = ["_uuid", "name"],
            where = [["name", "==", port]])
        # print(json.dumps(res,indent=4))
    
        # for re in res:
            # print(re)
            # print(json.dumps(re,indent=4))
            # if not re["queue_rules"]:
            #     continue
        bw_min_sum = 0
        try:
            for queue_rule in res[0]["queue_rules"]:
                if type(queue_rule) == list:
                    queue_rule = queue_rule[1]
                re = db.select(table = "Queue",
                # columns = ["_uuid", "bandwidth_min"],
                # where = [])
                where = [["_uuid", "==", ["uuid",queue_rule]]])
                # print(re)
                if not re:
                    continue
                for r in re:
                    if not r["bandwidth_min"]:
                        continue
                    bw_min_sum += int(r["bandwidth_min"][0][1])
        except:
            pass
        min_rate = DEFAULT_OVN_BW - bw_min_sum
        min_rate = f"{min_rate:,}"
        bw_min_list[ip]=min_rate
    print(bw_min_list)
    return bw_min_list
    



def put_demand(path,src_ip,dst_ip,vni,max_rate,min_rate,mod):
    max_rate = max_rate.replace(",", "")
    min_rate = min_rate.replace(",", "")
    demand = {}
    request = {}
    if path == "None":
        path = None
    demand['path'] = path
    demand['src_ip'] = src_ip
    demand['dst_ip'] = dst_ip
    # print(mod)

    if vni == 'None':
        vni = None

    if mod == "None":
        mod = None
    
    demand['mod'] = mod
    demand['vni'] = vni
    
    if max_rate:
        request['max-rate'] = max_rate
    if min_rate:
        request['min-rate'] = min_rate
    # demand['vm_traffic'] = False
    demand['request'] = request
    demand['vm_traffic'] = False

    print(demand)
 
    x = requests.put(request_url, json = demand)
    # print(x.request.url)
   
    
    return x

def put_demand_vm(src_ip,dst_ip,max_rate,min_rate,mod,virtual_topo,vni):
    # Remove input format (X,XXX,XXX)
    max_rate = (max_rate.replace(",", ""))
    min_rate = (min_rate.replace(",", ""))
    demand = {}
    request = {}
    # print(mod)
    
    if vni == "None":
        vni = None
    if mod == "None":
        mod = None
    demand['mod'] = mod
    demand['vni'] = vni
    if vni == None:
        return "missing vni",False
    vni = int(vni)
    if max_rate:
        request['max-rate'] = max_rate
    if min_rate:
        request['min-rate'] = min_rate
        
    demand['request'] = request
    # print(demand)
   

    max_rate = int(max_rate or 0)
    min_rate = int(min_rate or 1)

    

    if max_rate <= min_rate and max_rate and min_rate:
        return "Max rate <= Min rate",False
    # Check in virtual topo where VM belong 
    vm_ip_dict = {}
    for ls in virtual_topo:
        vni_loop = ls["vni"]
        lsps = ls["ports"]
        for lsp in lsps:
            if not lsp["outter_ip"]:
                continue
            vm_ip_dict[(lsp["inner_ip"][0],vni_loop)]=(lsp["outter_ip"],lsp['logical_port'])
    
    if (src_ip,vni) not in vm_ip_dict or (dst_ip,vni) not in vm_ip_dict:
        resp = "%s \n%s" %((src_ip,vni),vm_ip_dict)
        return "Cant find VM IP in Logical Topology"+resp, False
    bw_ovn_resv = get_bw_ovn_all(virtual_topo)
    if vm_ip_dict[(src_ip,vni)][0] == vm_ip_dict[(dst_ip,vni)][0]:
        # Internal VM traffic (check outerport)
        resp = "VM to VM traffic: "
        resv_min = int(bw_ovn_resv[vm_ip_dict[(src_ip,vni)][0]].replace(",", ""))

        if min_rate > resv_min:
            min_rate = f'{min_rate:,}'
            resp += 'Minrate: %s > Resv min rate: %s in HV %s' %\
            (min_rate,bw_ovn_resv[vm_ip_dict[(src_ip,vni)][0]],vm_ip_dict[(src_ip,vni)][0])
            return resp, False
        resp1,cond = handle_ovn_internal(vm_ip_dict[(src_ip,vni)][1],vm_ip_dict[(dst_ip,vni)][1],min_rate,max_rate,mod)
        resp += resp1
        return resp,cond
  
    
    cond = True
    cond1 = True
    # HV to HV traffic
    resp = "HV to HV traffic: \nSDN: "
    
    # demand['vm_traffic'] = (src_ip,dst_ip)
    demand['src_ip'] = vm_ip_dict[(src_ip,vni)][0]
    demand['dst_ip'] = vm_ip_dict[(dst_ip,vni)][0]
    # demand['vni'] = vm_ip_dict[dst_ip][2]
    demand['vm_src'] = src_ip
    demand['vm_dst'] = dst_ip
    demand['vm_traffic'] = True

    x = requests.put(request_url, json = demand)
    if x.status_code != 200: 
        cond = False
        resp += x.text
        return resp,cond
    resv_min = int(bw_ovn_resv[vm_ip_dict[(src_ip,vni)][0]].replace(",", ""))
    if min_rate > resv_min:
        min_rate = f'{min_rate:,}'
        resp += 'Minrate: %s > Resv min rate: %s in HV %s' %\
        cond == False
        (min_rate,bw_ovn_resv[vm_ip_dict[(dst_ip,vni)][0]],vm_ip_dict[(dst_ip,vni)][0])
    resp1,cond1 = handle_ovn_external(vm_ip_dict[(src_ip,vni)][0],vm_ip_dict[(src_ip,vni)][1],vm_ip_dict[(dst_ip,vni)][1],min_rate,max_rate,mod)
    # resp1,cond1 = handle_ovn_internal(vm_ip_dict[src_ip][1],vm_ip_dict[dst_ip][1],min_rate,max_rate,mod)
    
    resp += resp1
    if cond == False or cond1 == False:
        return resp, cond
    resp += "\nOVN: "
    
    resp2 = x.text
    
    # print(x.request.url)
    # resp1 = (json.loads(resp1))
    resp = resp + resp2
    
    return resp,cond

def get_bw_rev_format(virutal_topo):
    bw_resv = get_bw_ovn_all(virutal_topo)
    hv_ip = []
    for k in bw_resv.keys():
        hv_ip.append(k)
    if hv_ip:
        bw_resv['outer_ip'] = hv_ip
    return bw_resv



def mod_request(port,parent_rate,queue_list,src_ip):
    ovsdb_server = "tcp:"+ src_ip + ":6640"
    db = libovsdb.OVSDBConnection(ovsdb_server, "Open_vSwitch")
    get_port = db.select(table = "Port",
                columns = ['_uuid',"qos"],
                where = [["name", "==", port]])
    port_qos = get_port[0]['qos']
    # print(port_qos)
    # print("select qos result: %s" %(json.dumps(get_port, indent=4)))
    if not port_qos:
        parent_rate = ['map',[["max-rate",parent_rate]]]
        qos = db.insert(table = "QoS",
                        row = {"other_config":parent_rate,"type":QUEUE_TYPE},
                        refer = ["Port", "qos", ["name", "==", port]])
        # print("QOS: ",qos)
        get_port = db.select(table = "Port",
                columns = ['_uuid',"qos"],
                where = [["name", "==", port]])
        port_qos = get_port[0]['qos']
        
        list_queue = install_queue_port(db,queue_list,port_qos)
        return list_queue
    get_queue = db.select(table = "QoS",
                    columns = ['_uuid',"queues"],
                    where = [["_uuid", "==", ["uuid",port_qos]]])
    # print(get_queue[0]['queues'])
    # print("select qos result: %s" %(json.dumps(get_queue, indent=4)))

    if not get_queue[0]['queues']:
        list_queue = install_queue_port(db,queue_list,port_qos)
        return list_queue
    list_queue = get_queue[0]['queues'].copy()
    len_queue = len(list_queue)
    new_queue = []
    for key in range(len(queue_list)):
        max_rate = queue_list[key]['max-rate']
        min_rate = queue_list[key]['min-rate']
        burst = queue_list[key]['burst']

        config = ['map',[["max-rate",max_rate],["min-rate",min_rate],["burst",burst]]]
        res = db.insert(table = "Queue",
                    row = {"other_config":config,"external_ids":['map', [["queue_id",str(len_queue+key+1)]]]},)
        queue_uuid = res['uuid'][0]
        resp = {"max-rate":max_rate,"min-rate":min_rate,"burst":burst,"queue_id":len_queue+key+1} 
        new_queue.append(resp)

        # print(queue_uuid)
    
        list_queue.append([len_queue+key+1,['uuid',queue_uuid]])
    # print(list_queue)
    res_qos = db.update(table = "QoS",
                        row = {"queues":['map', list_queue]},
                        where = [["_uuid", "==", ["uuid",port_qos]]])
    return new_queue
    # tx.commit()
    # print(res_qos)



def install_queue_port(db,queue_list,port_qos):
    list_queue = []
    new_queue = []
    for key in range(len(queue_list)):
        max_rate = queue_list[key]['max-rate']
        min_rate = queue_list[key]['min-rate']
        burst = queue_list[key]['burst']

        config = ['map',[["max-rate",max_rate],["min-rate",min_rate],["burst",burst]]]
        res = db.insert(table = "Queue",
                    row = {"other_config":config,"external_ids":['map', [["queue_id",str(key+1)]]]})
        # print(res)
        resp = {"max-rate":max_rate,"min-rate":min_rate,"burst":burst,"queue_id":key+1} 
        new_queue.append(resp)

        queue_uuid = res['uuid'][0]
        # print(queue_uuid)
    
        list_queue.append([key+1,['uuid',queue_uuid]])
    # print(list_queue)
    res_qos = db.update(table = "QoS",
                        row = {"queues":['map', list_queue]},
                        where = [["_uuid", "==", ["uuid",port_qos]]])
    return new_queue
    # tx.commit()
    # print(res_qos)

def handle_ovn_internal(src_lp_name,dst_lp_name,min_rate,max_rate,mod):
    db = libovsdb.OVSDBConnection(ovn_nb, "OVN_Northbound")
    if not max_rate:
        max_rate = DEFAULT_OVN_BW

    res = db.select(table = "Logical_Switch_Port",
                columns = ["_uuid", "name"],
                where = [["name", "==", dst_lp_name]])
    queue_rule_list = res[0]["queue_rules"]
    # print("queue:",queue_rule_list)

    # print(json.dumps(queue_rule_list,indent=4))
    match = 'inport=="%s"' % src_lp_name
    # match = 'ip'
   
    if not queue_rule_list:
        # New queue
        # match = 'tcp'
        res = db.insert(table = "Queue",
                    row = {"direction":"to-lport","priority":200,
                        "match":match,"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                    refer = ["Logical_Switch_Port", "queue_rules", ["name", "==", dst_lp_name]])
        print(res)
        return "Success install new queue",True
    elif type(queue_rule_list) == list:
            for rule in queue_rule_list:
                print("FIND1 %s"%rule[1])
                get_source_lp = db.select(table = "Queue",
                        # columns = ['_uuid',"_uuid"],
                        where = [["_uuid", "==", ["uuid",rule[1]]]])
                print(json.dumps(get_source_lp,indent=4))
                if get_source_lp[0]['match'] != match:
                    continue
                if not mod:
                    print("DUP")
                    return "Duplicate Request", False
                # Modify exist queue
                res = db.update(table = "Queue",
                        row = {"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                        where = [["_uuid", "==", ["uuid",rule[1]]]])
                print(res)
                return "Success modify queue",True
            # New queue
            res = db.insert(table = "Queue",
                    row = {"direction":"to-lport","priority":200,
                        "match":match,"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                    refer = ["Logical_Switch_Port", "queue_rules", ["name", "==", dst_lp_name]])
            # print(res)
            return "Success install new queue",True
    elif type(queue_rule_list) == str:
        rule = queue_rule_list
        print("FIND2 %s"%rule)
        get_source_lp = db.select(table = "Queue",
                # columns = ['_uuid',"_uuid"],
                where = [["_uuid", "==", ["uuid",rule]]])
        print(json.dumps(get_source_lp,indent=4))
        if (get_source_lp[0]['match'] != match):
            # New Queue
            res = db.insert(table = "Queue",
                    row = {"direction":"to-lport","priority":200,
                        "match":match,"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                    refer = ["Logical_Switch_Port", "queue_rules", ["name", "==", dst_lp_name]])
            print(res)
          
            return "Success install new queue",True
        if not mod:
            # print("DUP")
            return "Duplicate Request", False
        # Modify exist queue
        res = db.update(table = "Queue",
                row = {"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                where = [["_uuid", "==", ["uuid",rule]]])
        print(res)
        return "Success modify queue",True


def handle_ovn_external(src_ip,src_lp_name,dst_lp_name,min_rate,max_rate,mod):
    db = libovsdb.OVSDBConnection(ovn_nb, "OVN_Northbound")
    if not max_rate:
        max_rate = DEFAULT_OVN_BW

    res = db.select(table = "Logical_Switch_Port",
                columns = ["_uuid", "name"],
                where = [["name", "==", dst_lp_name]])
    queue_rule_list = res[0]["queue_rules"]
    # print("queue:",queue_rule_list)

    # print(json.dumps(queue_rule_list,indent=4))
    match = 'inport=="%s"' % src_lp_name
    # match = 'ip'
   
    if not queue_rule_list:
        # New queue
        # Default Tunnel port name of HV
        port_tun = "ovn-cca09a-0"
        queue_new = [{"max-rate":str(max_rate),"min-rate":str(min_rate),"burst":"0"}]
        queue_ret = mod_request(port_tun,str(DEFAULT_OVN_BW),queue_new,src_ip)
        # match = 'tcp'
        queue_id = queue_ret[0]["queue_id"]

        res = db.insert(table = "Queue",
                    row = {"direction":"to-lport","priority":200,"id_queue":queue_id,
                        "match":match,"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                    refer = ["Logical_Switch_Port", "queue_rules", ["name", "==", dst_lp_name]])
        res = db.insert(table = "Queue",
                    row = {"direction":"from-lport","priority":200,"id_queue":queue_id,
                        "match":match,"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                    refer = ["Logical_Switch_Port", "queue_rules", ["name", "==", dst_lp_name]])
        print(res)
        return "Success install new queue",True
    elif type(queue_rule_list) == list:
            for rule in queue_rule_list:
                print("FIND1 %s"%rule[1])
                get_source_lp = db.select(table = "Queue",
                        # columns = ['_uuid',"_uuid"],
                        where = [["_uuid", "==", ["uuid",rule[1]]]])
                print(json.dumps(get_source_lp,indent=4))
                if get_source_lp[0]['match'] != match:
                    continue
                if not mod:
                    print("DUP")
                    return "Duplicate Request", False
                # Modify exist queue
                res = db.update(table = "Queue",
                        row = {"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                        where = [["_uuid", "==", ["uuid",rule[1]]]])
                print(res)
                return "Success modify queue",True
            # New queue
             # Default Tunnel port name of HV
            port_tun = "ovn-cca09a-0"
            # port_tun = "br-int"

            queue_new = [{"max-rate":str(max_rate),"min-rate":str(min_rate),"burst":"0"}]
            queue_ret = mod_request(port_tun,str(DEFAULT_OVN_BW),queue_new,src_ip)
            # match = 'tcp'
            queue_id = queue_ret[0]["queue_id"]
            res = db.insert(table = "Queue",
                    row = {"direction":"to-lport","priority":200,"id_queue":queue_id,
                        "match":match,"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                    refer = ["Logical_Switch_Port", "queue_rules", ["name", "==", dst_lp_name]])
            res = db.insert(table = "Queue",
                    row = {"direction":"from-lport","priority":200,"id_queue":queue_id,
                        "match":match,"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                    refer = ["Logical_Switch_Port", "queue_rules", ["name", "==", dst_lp_name]])
            print(res)
            return "Success install new queue",True
    elif type(queue_rule_list) == str:
        rule = queue_rule_list
        print("FIND2 %s"%rule)
        get_source_lp = db.select(table = "Queue",
                # columns = ['_uuid',"_uuid"],
                where = [["_uuid", "==", ["uuid",rule]]])
        print(json.dumps(get_source_lp,indent=4))
        if (get_source_lp[0]['match'] != match):
            # New Queue
              # Default Tunnel port name of HV
            port_tun = "ovn-cca09a-0"
            queue_new = [{"max-rate":str(max_rate),"min-rate":str(min_rate),"burst":"0"}]
            queue_ret = mod_request(port_tun,str(DEFAULT_OVN_BW),queue_new,src_ip)
            # match = 'tcp'
            queue_id = queue_ret[0]["queue_id"]
            res = db.insert(table = "Queue",
                    row = {"direction":"to-lport","priority":200,"id_queue":queue_id,
                        "match":match,"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                    refer = ["Logical_Switch_Port", "queue_rules", ["name", "==", dst_lp_name]])
            res = db.insert(table = "Queue",
                    row = {"direction":"from-lport","priority":200,"id_queue":queue_id,
                        "match":match,"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                    refer = ["Logical_Switch_Port", "queue_rules", ["name", "==", dst_lp_name]])
            print(res)
          
            return "Success install new queue",True
        if not mod:
            # print("DUP")
            return "Duplicate Request", False
        # Modify exist queue
        res = db.update(table = "Queue",
                row = {"bandwidth_max":['map',[["rate",max_rate]]],"bandwidth_min":['map',[["min",min_rate]]]},
                where = [["_uuid", "==", ["uuid",rule]]])
        print(res)
        return "Success modify queue",True

            
def put_path_find(src_ip,dst_ip):
    demand = {}
    demand['src_ip'] = src_ip
    demand['dst_ip'] = dst_ip   

    x = requests.put(path_find_url, json = demand)
    # print(x.request.url)
    return x

def del_qos_all(port):
    ovsdb_server = 'tcp:192.168.0.116:6640'
    db = libovsdb.OVSDBConnection(ovsdb_server, "Open_vSwitch")

    get_port = db.select(table = "Port",
                        columns = ['_uuid',"qos"],
                        where = [["name", "==", port]],)
    port_qos = get_port[0]['qos']
    print(port_qos)


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
if __name__ == '__main__':
    # x= get_switch(19)
    # x = get_switch_all()
    
    
    src_ip = '10.1.1.5'
    dst_ip = '10.2.1.5'
    min_rate = 1000000000
    max_rate = 2000000000
    path = [1,2,3]
    path = 'None'
    mod = 1
    # x = put_demand(path,src_ip,dst_ip,vni,max_rate,min_rate)
    # x = put_path_find(src_ip,dst_ip)
    # print(x.status_code)
    # # print(x.content)
    # parser = (json.loads(x.text))
    # print(json.dumps(parser,indent=4))
    # print(parser)


    virtual_topo = get_virtual_topo()
    # print(json.dumps(res[1],indent=4))
    # put_demand_vm(path,src_ip,dst_ip,max_rate,min_rate,None,virtual_topo)

    # print(res)

    # del_qos_all("tapbcd579a1-27")
    # del_qos_all("tap35f82979-1d")

    hv_ip = "192.168.0.116"
    res = get_bw_ovn_all(virtual_topo)
    # print(res)
