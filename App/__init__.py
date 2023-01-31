# -*- coding: utf-8 -*
# @Time    : 2022/2/10 15:03
# @Author  : liuy
# @File    : __init__.py
import os

from App.admin import admin
from App.ext import db
from App.home import home
from flask import Flask


def create_app():
    app = Flask(__name__)
    # 配置文件
    app.config['SQLALCHEMY_DATABASE_URI'] = 'mysql+pymysql://root:513921@127.0.0.1:3306/movie'
    app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = True
    app.config['SECRET_KEY'] = "6bd749587aad49399f674b202a07d56f"
    app.config['SQLALCHEMY_COMMIT_TEARDOWN'] = True
    # app.config['UPLOADED_PHOTOS_DEST'] = os.path.join(os.path.dirname(__file__), "static/uploads/users")
    # 加载数据库
    db.init_app(app)
    # 创建蓝图
    app.register_blueprint(home)
    app.register_blueprint(admin, url_prefix='/admin')
    return app
