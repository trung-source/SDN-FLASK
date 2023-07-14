import requests
import json

ryu_ip = 'http://127.0.0.1:8080'

switch_all_url = ryu_ip +'/simpleswitch/allswitch/'
switch_url = ryu_ip +'/simpleswitch/switch/'
request_url = ryu_ip + '/simpleswitch/request/'
path_find_url = ryu_ip + '/simpleswitch/pathfind/'

host_url = ryu_ip +'/simpleswitch/host/'


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


def put_demand(path,src_ip,dst_ip,vni,max_rate,min_rate):
    max_rate = max_rate.replace(",", "")
    min_rate = min_rate.replace(",", "")
    demand = {}
    request = {}
    demand['path'] = path
    demand['src_ip'] = src_ip
    demand['dst_ip'] = dst_ip
    if vni == 'None':
        vni = None
    
    demand['vni'] = vni
    
    if max_rate:
        request['max-rate'] = max_rate
    if min_rate:
        request['min-rate'] = min_rate
        
    demand['request'] = request
    # print(demand)
 
    x = requests.put(request_url, json = demand)
    # print(x.request.url)
   
    
    return x


def put_path_find(src_ip,dst_ip):
    demand = {}
    demand['src_ip'] = src_ip
    demand['dst_ip'] = dst_ip
    
        
    print(demand)
 
    x = requests.put(path_find_url, json = demand)
    # print(x.request.url)
   
    
    return x

if __name__ == '__main__':
    # x= get_switch(19)
    x = get_switch_all()
    
    
    # src_ip = '10.0.0.1'
    # dst_ip = '10.0.0.3'
    # vni = 1
    # min_rate = 1000000000
    # max_rate = 2000000000
    # path = [1,2,3]
    # x = put_demand(path,src_ip,dst_ip,vni,max_rate,min_rate)
    # x = put_path_find(src_ip,dst_ip)
    
    print(x.status_code)
    # print(x.content)
    parser = (json.loads(x.text))
    print(json.dumps(parser,indent=4))
    print(parser)