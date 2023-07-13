import requests
import json

ryu_ip = 'http://127.0.0.1:8080'

switch_url = ryu_ip +'/simpleswitch/switch/'
request_url = ryu_ip + '/simpleswitch/request/'




def get_switch(switch_id):
    url = switch_url + str(switch_id)
    x = requests.get(url)
    parser = json.loads(x.text)
    print(json.dumps(parser,indent=4))
    print(parser)


def put_demand(path,src_ip,dst_ip,vni,max_rate,min_rate):
    demand = {}
    request = {}
    demand['path'] = path
    demand['src_ip'] = src_ip
    demand['dst_ip'] = dst_ip
    
    if vni:
        demand['vni'] = vni
    
    if max_rate:
        request['max-rate'] = str(max_rate)
    if min_rate:
        request['min-rate'] = str(min_rate)
        
    demand['request'] = request
    print(demand)
 
    x = requests.put(request_url, json = demand)
    print(x.request.url)
    print(x.status_code)
    parser = json.loads(x.text)
    print(json.dumps(parser,indent=4))
    print(parser)

if __name__ == '__main__':
    # get_switch(1)
    
    src_ip = '10.0.0.1'
    dst_ip = '10.0.0.3'
    vni = 1
    min_rate = 1000000000
    max_rate = 2000000000
    path = [1,2,3]
    put_demand(path,src_ip,dst_ip,vni,max_rate,min_rate)