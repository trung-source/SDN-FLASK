from flask import Flask
from flask_sqlalchemy import SQLAlchemy
from os import path
from flask_login import LoginManager, login_manager

db = SQLAlchemy()
DB_NAME = 'database.db'



def create_app():
    app = Flask(__name__,static_url_path='')
    app.config['SECRET_KEY'] = "APP_SECRET_KEY"
    app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'

    db.init_app(app)


    from .views import views
    # from .auth import auth

    app.register_blueprint(views, url_prefix = '/')                                     # URL se duoc update sau /

     # load file de tao class truoc khi tao web 
    create_database(app)


    # login_manager = LoginManager()
    # login_manager.login_view = 'auth.login'                                           # Neu chua dang nhap thi o trang login
    # login_manager.init_app(app)                                                         # Dang dung app nao




    return app

def create_database(app):
    if not path.exists('web/' + DB_NAME):                           # Neu khong ton tai duong dan thi tao file
        db.create_all(app=app)
        print("Created database!")
