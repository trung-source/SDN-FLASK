from flask import Blueprint, render_template,request,flash                                                # Là thiết kế cho ứng dụng: từng trang web (URL)
from flask_login import login_required

from . import source
import json

views = Blueprint('views',__name__)                                                          # Đặt cùng tên cho đơn giản
@views.route('/', methods = ['GET','POST'])
# @login_required
def home(): 

    switch_list = source.get_switch_all().text
    switch_list = (json.loads(switch_list))
    
    
    host_list = source.get_host().text
    host_list = (json.loads(host_list))
    
        
 
    
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
        return render_template("home.html",switch_list = switch_list,host_list=host_list,
                               path_pw=resp,src_ip_find=src_ip,dst_ip_find=dst_ip)
        
    if request.method == 'POST' and "form2-submit" in request.form:
        src_ip = request.form.get('src_ip_find')
        dst_ip = request.form.get('src_ip_find')
        
        
        
    
    
    return render_template("home.html",switch_list = switch_list,host_list=host_list)

