# -*- coding: utf-8 -*
# @Time    : 2022/2/10 15:04
# @Author  : liuy
# @File    : __init__.py

from flask import Blueprint

home = Blueprint("home", __name__)

import App.home.views
