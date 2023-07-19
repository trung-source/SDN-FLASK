from flask import Blueprint, render_template,request,flash                                                # Là thiết kế cho ứng dụng: từng trang web (URL)
from flask_login import login_required

from . import source
import json
import ast

views = Blueprint('views',__name__)                                                          # Đặt cùng tên cho đơn giản
@views.route('/', methods = ['GET','POST'])
# @login_required
def home(): 

    switch_list = source.get_switch_all().text
    switch_list = (json.loads(switch_list))
    
    
    host_list = source.get_host().text
    host_list = (json.loads(host_list))
    
        
 
    if request.method == 'POST' and "virtual-submit" in request.form:
            virutal_topo = source.get_virtual_topo().text
            print("aaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
            print(virutal_topo)
            flash("Get logical topo success", category = 'success')
            virutal_topo = (json.loads(virutal_topo))
            return render_template("home.html",virutal_topo=virutal_topo)
    
    if request.method == 'POST' and "form-submit" in request.form:
        src_ip = request.form.get('src_ip_find')
        dst_ip = request.form.get('dst_ip_find')
        
        # print(type(src_ip),dst_ip)
        # table = [[1,2,3],[4,5,6]]
        resp = source.put_path_find(src_ip,dst_ip)
        if resp.status_code != 200: 
            flash(resp.text, category = 'error')
            return render_template("home.html",switch_list = switch_list,host_list=host_list,
                                   src_ip_find=src_ip,dst_ip_find=dst_ip)
        flash("Path find success", category = 'success')
        resp = (json.loads(resp.text))
        print(resp)
        
        return render_template("home.html",switch_list = switch_list,host_list=host_list,
                               path_pw=resp,src_ip_find=src_ip,dst_ip_find=dst_ip)
        
    if request.method == 'POST' and "form2-submit" in request.form:
        src_ip = request.form.get('src_ip_request')
        dst_ip = request.form.get('dst_ip_request')
        max_rate = request.form.get('max-rate')
        min_rate= request.form.get('min-rate')
        vni = (request.form.get('vni'))
        path_request = request.form.get('path_request')
        path_request = ast.literal_eval('['+ path_request + ']')
        # max_rate = max_rate.replace(",", "")
        # min_rate = min_rate.replace(",", "")
        mod = request.form.get('modcheck')
    
        
        
        resp = source.put_demand(path_request,src_ip,dst_ip,vni,max_rate,min_rate,mod)
        if resp.status_code != 200: 
            flash(resp.text, category = 'error')
            return render_template("home.html",switch_list = switch_list,host_list=host_list,
                                   demand=request.form)
        
        flash("Request accpeted", category = 'success')
        resp = (json.loads(resp.text))
        return render_template("home.html",switch_list = switch_list,host_list=host_list,
                               demand=request.form,max_rate=max_rate,min_rate=min_rate)
        
        
        
        
    
    
    return render_template("home.html",switch_list = switch_list,host_list=host_list)

