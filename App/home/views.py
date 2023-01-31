# -*- coding: utf-8 -*
# @Time    : 2022/2/10 15:05
# @Author  : liuy
# @File    : views.py
import os
import uuid
from functools import wraps

from flask import render_template, redirect, url_for, session, flash, request, Flask
from werkzeug.security import generate_password_hash
from werkzeug.utils import secure_filename
from .forms import LoginForm, RegistForm, UserdetailForm, PwdForm, CommentForm
from App.models import db, Comment, Moviecol, Preview
from ..admin.views import change_filename
from ..models import User, Userlog, Tag, Movie
from . import home


# 定义装饰器，必须登录后才能访问
def user_login_req(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if session.get('home', None) is None:
            return redirect(url_for('home.play', id=1, page=1))
        return func(*args, **kwargs)
    return decorated_function


@home.route("/login/", methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():     # 如果用户输入的用户名和密码符合验证条件
        data = form.data              # 获取用户输入的表单数据
        user = User.query.filter_by(name=data.get("name")).first()      # 根据用户名查询数据库，返回第一个查询结果
        if user == None:              # 如果从数据库中查不到用户名
            flash("会员账号不存在,请重新输入！", "err")
            return redirect(url_for("home.login"))
        elif not user.check_pwd(data.get("pwd")):         # 如果从数据库查询到用户名但密码不匹配
            flash("用户名或密码错误！", "err")
            return redirect(url_for("home.login"))
        session['user'] = user.name             # 定义session信息
        session['user_id'] = user.id
        userlog = Userlog(                     # 定义用户登录日志
            user_id=user.id,
            ip=request.remote_addr
        )
        db.session.add(userlog)                 # 添加用户登录日志
        db.session.commit()
        return redirect(url_for("home.user"))
    return render_template("home/login.html", form=form)


@home.route("/logout/")
def logout():
    session.pop("user", None)            # 从session中删除用户名
    session.pop("user_id", None)         # 从session中删除用户id
    return redirect(url_for("home.login"))


@home.route("/register/", methods=["GET", "POST"])
def register():
    form = RegistForm()                    # 获取用户输入的注册信息数据
    if form.validate_on_submit():          # 如果用户输入的注册数据通过form基础验证
        data = form.data                   # 获取用户输入的表单数据
        user = User(
            name=data.get("name"),        # 从表单中获取用户输入的用户名
            email=data.get("email"),      # 从表单中获取用户输入的邮箱地址
            phone=data.get("phone"),      # 从表单中获取用户输入的手机号
            pwd=generate_password_hash(data.get("pwd")),          # 从表单中获取用户输入的密码并进行加密
            uuid=uuid.uuid4().hex         # 生成uuid,保证唯一性
        )
        db.session.add(user)             # 添加用户
        db.session.commit()              # 向数据库提交用户注册信息
        flash("注册成功！", "ok")
        return redirect(url_for("home.login"))
    return render_template("home/register.html", form=form)


@home.route("/<int:page>/", methods=['GET'])
@home.route("/", methods=['GET'])
def index(page=None):
    tags = Tag.query.all()              # 获取数据库中所有的电影标签
    page_data = Movie.query             # 从数据库中获取所有的电影信息    page_data就是电影对象

    tid = request.args.get("tid", 0)    # 获取用户请求的电影标签id
    if int(tid) != 0:
        page_data = page_data.filter_by(tag_id=int(tid))    # 根据用户请求的页码进行过滤

    star = request.args.get("star", 0)    # 获取用户请求的电影星级id
    if int(star) != 0:
        page_data = page_data.filter_by(star=int(star))    # 根据用户请求的电影星级id进行过滤

    time = request.args.get("time", 0)    # 获取用户请求的电影添加时间
    if int(time) != 0:
        page_data = page_data.order_by(Movie.addtime)    # 获取用户请求的电影添加时间进行过滤

    pm = request.args.get("pm", 0)    # 获取用户请求的电影播放次数
    if int(pm) != 0:
        page_data = page_data.order_by(Movie.playnum)    # 获取用户请求的电影播放次数进行过滤

    cm = request.args.get("cm", 0)    # 获取用户请求的电影评论次数
    if int(cm) != 0:
        page_data = page_data.order_by(Movie.commentnum)    # 获取用户请求的电影评论次数进行过滤

    if page is None:    # 获取用户请求的页数
        page = 1
    page_data = page_data.paginate(page=page, per_page=10)    # 进行分页，每页显示10条电影数据

    p = dict(
        tid=tid,
        star=star,
        time=time,
        pm=pm,
        cm=cm
    )    # 定义返回给前端页面的字典信息
    return render_template("home/index.html", tags=tags, p=p, page_data=page_data)


# 会员详情
@home.route("/user/", methods=['GET', 'POST'])
def user():
    if session.get("user_id") is None:
        form = LoginForm()
        return render_template("home/login.html", form=form)
    else:
        form = UserdetailForm()
        user = User.query.get(int(session.get("user_id")))
        form.face.validators = []
        if request.method == 'GET':
            form.name.data = user.name
            form.email.data = user.email
            form.phone.data = user.phone
            form.info.data = user.info

        if form.validate_on_submit():
            data = form.data
            # 验证头像是否存在
            path = "App/static/uploads/users/"
            file_face = secure_filename(form.face.data.filename)
            if not os.path.exists(path):     # 判断括号里的文件是否存在，括号内的可以是文件路径。
                os.makedirs(path)            # 递归创建目录
                os.chmod(path)         # 修改目录权限
            user.face = change_filename(file_face)           # 修改文件名称
            form.face.data.save(path + user.face)
            # 验证用户名是否存在
            name_count = User.query.filter_by(name=data.get("name")).count()
            if data.get("name") != user.name and name_count == 1:
                flash("用户名已经存在,请重新输入！", "err")
                return redirect(url_for("home.user"))
            # 验证邮箱是否存在
            email_count = User.query.filter_by(email=data.get("email")).count()
            if data.get("email") != user.email and email_count == 1:
                flash("邮箱已经存在，请重新输入！", "err")
                return redirect(url_for("home.user"))
            # 验证手机号是否存在
            phone_count = User.query.filter_by(phone=data.get('phone')).count()
            if data.get("phone") != user.phone and phone_count == 1:
                flash("手机号已经存在，请重新输入！", "err")
                return redirect(url_for("home.user"))
            user = User(
                name=data.get("name"),
                email=data.get("email"),
                phone=data.get("phone"),
                info=data.get("info"),
            )
            db.session.add(user)
            db.session.commit()
            flash("修改已经保存！", "ok")
            return redirect(url_for("home.user"))
        return render_template("home/user.html", form=form, user=user)


@home.route("/pwd/", methods=['GET', 'POST'])
def pwd():
    form = PwdForm()
    print(form.data)
    if form.validate_on_submit():
        data = form.data
        print(data)
        user = User.query.filter_by(name=session.get("user")).first()
        if not user.check_pwd(data.get("pwd")):
            flash("旧密码输入错误，请重新输入！", "err")
            return redirect(url_for("home.pwd"))

        from werkzeug.security import generate_password_hash
        user.pwd = generate_password_hash(data.get("new_pwd"))
        db.session.add(user)
        db.session.commit()
        flash("修改密码成功，请重新登录！", "ok")
        return redirect(url_for("home.logout"))
    return render_template("home/pwd.html", form=form)


# 用户评论
@home.route("/comments/<int:page>/")
def comments(page=None):
    if page is None:
        page = 1
    page_data = Comment.query.join(Movie).join(User).filter(
        Movie.id == Comment.movie_id,
        User.id == session["user_id"]
    ).order_by(Comment.id).paginate(page=page, per_page=10)
    return render_template("home/comments.html", page_data=page_data)


@home.route("/loginlog/<int:page>/", methods=['GET'])
def loginlog(page=None):
    if page is None:
        page = 1
    page_data = Userlog.query.filter_by(user_id=int(session.get("user_id"))).order_by(
        Userlog.id).paginate(page=page, per_page=10)

    return render_template("home/loginlog.html", page_data=page_data)


# 电影收藏表
@home.route("/moviecol/<int:page>/")
def moviecol(page=None):
    if page is None:
        page = 1
    page_data = Moviecol.query.join(Movie).join(User).filter(
        Movie.id == Moviecol.movie_id,
        User.id == session.get("user_id")
    ).order_by(Moviecol.id).paginate(page=page, per_page=10)
    return render_template("home/moviecol.html", page_data=page_data)


# 搜索页面
@home.route('/search/', methods=['post','get'])
def search(page=None):
    if page is None:
        page = 1
    keyword = request.args.get("keyword", "")
    movie_count = Movie.query.filter(
        Movie.title.ilike('%' + keyword + '%')
    ).count()
    page_data = Movie.query.filter(
        Movie.title.ilike('%' + keyword + '%')
    ).order_by(
        Movie.addtime.desc()
    ).paginate(page=page, per_page=10)
    page_data.key = keyword
    return render_template("home/search.html", movie_count=movie_count, keyword=keyword, page_data=page_data)


# 首页轮播图页面
@home.route('/animation/')
def animation():
    data = Preview.query.all()
    for v in data:
        v.id = v.id - 1
    return render_template("home/animation.html", data=data)


# 电影
@home.route('/play/<int:id>/<int:page>/', methods=["GET", "POST"])
def play(id=None, page=None):
    # 查询出相关联的标签
    movie = Movie.query.join(Tag).filter(
        Tag.id == Movie.tag_id,
        Movie.id == int(id)
    ).first_or_404()

    if page is None:
        page = 1
    page_data = Comment.query.join(Movie).join(User).filter(
        Movie.id == movie.id,
        User.id == Comment.user_id
    ).order_by(Comment.addtime.desc()).paginate(page=page, per_page=10)
    form = CommentForm()
    # 必须登录才能评论  session中的值是该用户的名字
    name = session.get("user")
    user = User.query.filter_by(name=name).first()
    if form.validate_on_submit() and 'user' in session:
        data = form.data
        comment = Comment(
            content=data["content"],
            movie_id=movie.id,
            user_id=session["user_id"]
        )
        db.session.add(comment)
        db.session.commit()
        movie.commentnum = movie.commentnum + 1
        db.session.add(movie)
        db.session.commit()
        flash("添加评论成功！", "ok")
        return redirect(url_for('home.play', id=movie.id, page=1))
    movie.playnum = movie.playnum + 1
    db.session.add(movie)
    db.session.commit()
    return render_template("home/play.html", movie=movie, form=form, page_data=page_data)


@home.route("/moviecol/add/", methods=["GET"])
# @user_login_req
def moviecol_add():
    uid = request.json.get("uid")
    mid = request.json.get("mid")
    moviecol = Moviecol.query.filter_by(
        user_id=int(uid),
        movie_id=int(mid)
    ).count()
    # 已收藏
    if moviecol == 1:
        data = dict(ok=0)
    # 未收藏进行收藏
    if moviecol == 0:
        moviecol = Moviecol(
            user_id=int(uid),
            movie_id=int(mid)
        )
        db.session.add(moviecol)
        db.session.commit()
        data = dict(ok=1)
    import json
    return json.dumps(data)