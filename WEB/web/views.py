from flask import Blueprint, render_template,request,flash                                                # Là thiết kế cho ứng dụng: từng trang web (URL)
from flask_login import login_required

from . import source


views = Blueprint('views',__name__)                                                          # Đặt cùng tên cho đơn giản
@views.route('/', methods = ['GET','POST'])
# @login_required
def home():
    if request.method == 'POST':
        note = request.form.get('note')
        if note:
            flash('Note da duoc tao!', category = 'success')
        
    return render_template("home.html")

