# -*- coding: utf-8 -*
# @Time    : 2022/2/10 15:05
# @Author  : liuy
# @File    : views.py
import datetime
import os
import uuid
from werkzeug.utils import secure_filename
from . import admin
from functools import wraps
from flask import render_template, redirect, url_for, session, request, abort, flash,Flask
from App.models import db, Admin, Auth, Role, Adminlog, Tag, Movie, Oplog, Preview, User, Comment, Moviecol, Userlog
from .forms import LoginForm, PwdForm, TagForm, MovieForm, PreviewForm, AuthForm, RoleForm, AdminForm
app = Flask(__name__)

movie_path = "App/static/video/movie/"
logo_path = "App/static/video/logo/"


# 权限控制装饰器   根据session里面保存的管理员id查询出对于的角色，根据角色查询出权限，根据权限查询出能够访问的路径
def admin_auth(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        admin = Admin.query.join(Role).filter(      # 拿到管理员的name
            Role.id == Admin.role_id,
            Admin.id == session.get("admin_id")
        ).first()
        auths = admin.role.auths                   # 拿到角色表的权限值
        if auths:
            auths = list(map(lambda v: int(v), auths.split(",")))
            auth_list = Auth.query.all()         # 拿到权限表里所有的对象
            urls = [v.url for v in auth_list for val in auths if val == v.id]  # 根据对象拿到他所对应的url
            rule = request.url_rule   # 查询请求封装的url
            if str(rule) not in urls:
                abort(404)
            return func(*args, **kwargs)
        abort(404)
    return decorated_function


# 定义装饰器，必须登录后才能访问后台管理页面
def admin_login_req(func):
    @wraps(func)
    def decorated_function(*args, **kwargs):
        if session.get('admin', None) is None:
            return redirect(url_for('admin.login', next=request.url))
        return func(*args, **kwargs)
    return decorated_function


# 上下文应用处理器
# 封装全局变量，并将其展现到模版里
@admin.context_processor
def tpl_extra():
    try:
        admin = Admin.query.filter_by(name=session["admin"]).first()		# 从session中获取admin的值，并在数据库中进行查询
    except:
        admin = None
    data=dict(
        online_time=datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        logo="user3-128x128.jpg",
        admin=admin,
    )
    return data


# 主页
@admin.route('/')
@admin_login_req
@admin_auth
def index():
    return render_template("admin/index.html")


# 登录
@admin.route('/login/', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=data['account']).first()
        if admin.check_pwd(data.get("pwd")):
            flash("旧密码错误，请重新输入！", "err")
            return redirect(url_for("admin.login"))

        session['admin'] = data.get("account")
        session['admin_id'] = admin.id
        adminlog = Adminlog(
            admin_id=admin.id,
            ip=request.remote_addr
        )
        db.session.add(adminlog)
        db.session.commit()
        return redirect(request.args.get("next") or url_for('admin.index'))
    return render_template("admin/login.html", form=form)


# 退出
@admin.route('/logout/')
@admin_login_req
def logout():
    session.pop("admin", None)
    session.pop("admin_id", None)
    return redirect(url_for("admin.login"))


# 修改密码
@admin.route('/pwd/', methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def pwd():
    form = PwdForm()
    if form.validate_on_submit():
        data = form.data
        admin = Admin.query.filter_by(name=session.get("admin")).first()

        from werkzeug.security import generate_password_hash
        admin.pwd = generate_password_hash(data.get("new_pwd"))
        db.session.add(admin)
        db.session.commit()
        flash("修改密码成功，请重新登录！", "ok")
        return redirect(url_for("admin.logout"))
    return render_template("admin/pwd.html", form=form)


# 标签列表
@admin.route("/tag/list/<int:page>/", methods=["GET"])
@admin_login_req
@admin_auth
def tag_list(page=None):
    """
    标签列表
    """
    if page is None:
        page = 1
    page_data = Tag.query.order_by(
        Tag.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/tag_list.html", page_data=page_data)


# 添加标签
@admin.route('/tag/add/', methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def tag_add():
    form = TagForm()
    if form.validate_on_submit():
        data = form.data
        tag = Tag.query.filter_by(name=data.get("name")).count()
        if tag == 1:
            flash("标签名称已存在，请重新输入！", "err")
            return redirect(url_for("admin.tag_add"))
        tag = Tag(name=data.get("name"))
        db.session.add(tag)
        db.session.commit()
        flash("添加标签成功！", "ok")
        oplog = Oplog(
            admin_id=session.get("admin_id"),
            ip=request.remote_addr,
            reason="添加标签:%s" % data.get("name")
        )
        db.session.add(oplog)
        db.session.commit()
        return redirect(url_for("admin.tag_list", page=1))
    return render_template("admin/tag_add.html", form=form)


# 编辑标签
@admin.route('/tag/edit/<int:id>/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def tag_edit(id=None):
    form = TagForm()
    tag = Tag.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        tag_count = Tag.query.filter_by(name=data.get("name")).count()
        if tag.name != data.get("name") and tag_count == 1:
            flash("标签名称已存在，请重新输入！", "err")
            return redirect(url_for("admin.tag_edit", id=id))
        tag.name = data.get("name")
        db.session.add(tag)
        db.session.commit()
        flash("修改标签成功！", "ok")
        return redirect(url_for("admin.tag_list", page=1))
    return render_template("admin/tag_edit.html", form=form, tag=tag)


# 标签删除
@admin.route('/tag/del/<int:id>/', methods=["GET"])
@admin_login_req
@admin_auth
def tag_del(id=None):
    tag = Tag.query.filter_by(id=id).first_or_404()
    db.session.delete(tag)
    db.session.commit()
    flash("删除标签成功!", "ok")
    return redirect(url_for("admin.tag_list", page=1))


# 电影列表
@admin.route('/movie/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def movie_list(page=None):
    if page is None:
        page = 1
    page_data = Movie.query.join(Tag).filter(Tag.id == Movie.tag_id).order_by(
        Movie.addtime.desc()
    ).paginate(page=page, per_page=10)
    return render_template("admin/movie_list.html", page_data=page_data)


# 修改文件名称
def change_filename(filename):
    fileinfo = os.path.splitext(filename)
    filename = datetime.datetime.now().strftime("%Y%m%d%H%M%S") + str(uuid.uuid4().hex) + fileinfo[-1]
    return filename


# 添加电影
@admin.route('/movie/add/', methods=["POST", "GET"])
@admin_login_req
@admin_auth
def movie_add():
    form = MovieForm()
    form.tag_id.choices = [(tag.id, tag.name) for tag in Tag.query.all()]
    if form.validate_on_submit():
        data = form.data
        file_url = secure_filename(form.url.data.filename)      # 获取更加安全的文件
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(movie_path):
            os.makedirs(movie_path)
            os.chmod(movie_path, "rw")
        url = change_filename(file_url)
        logo = change_filename(file_logo)
        form.url.data.save(movie_path + url)
        form.logo.data.save(logo_path + logo)

        movie = Movie(
            title=data.get("title"),
            url=url,
            info=data.get("info"),
            star=int(data.get("star")),
            tag_id=int(data.get("tag_id")),
            area=data.get("area"),
            release_time=data.get("release_time"),
            length=data.get("length"),
            logo=logo,
            playnum=0,
            commentnum=0,
        )
        db.session.add(movie)
        db.session.commit()
        flash("添加电影成功!", "ok")
        return redirect(url_for("admin.movie_list", page=1))

    return render_template("admin/movie_add.html", form=form)


# 编辑电影
@admin.route("/movie/edit/<int:id>/", methods=["GET", "POST"])
@admin_login_req
@admin_auth
def movie_edit(id=None):
    form = MovieForm()
    form.tag_id.choices = form.tag_id.choices = [(tag.id, tag.name) for tag in Tag.query.all()]
    form.url.validators = []
    form.logo.validators = []
    movie = Movie.query.get_or_404(int(id))

    if request.method == 'GET':
        form.info.data = movie.info
        form.tag_id.data = movie.tag_id
        form.star.data = movie.star
    if form.validate_on_submit():
        data = form.data
        movie_count = Movie.query.filter_by(title=data["title"]).count()
        if movie_count == 1 and movie.title != data.get("title"):
            flash("片名已经存在，请重新输入!", "err")
            return redirect(url_for("admin.movie_edit", id=id))
        if not os.path.exists(movie_path):
            os.makedirs(movie_path)
            os.chmod(movie_path)
        if form.url.data.filename != "":
            file_url = secure_filename(form.url.data.filename)
            movie_url = change_filename(file_url)
            form.url.data.save(movie_path + movie_url)
        if form.logo.data.filename != "":
            file_logo = secure_filename(form.logo.data.filename)
            movie_logo = change_filename(file_logo)
            form.logo.data.save(logo_path + movie_logo)
        movie = Movie(
            title=data.get("title"),
            info=data.get("info"),
            star=data.get("star"),
            tag_id=data.get("tag_id"),
            area=data.get("area"),
            release_time=data.get("release_time"),
            length=data.get("length"),
        )
        db.session.add(movie)
        db.session.commit()
        flash("修改电影成功!", "ok")
        return redirect(url_for("admin.movie_list", page=1))
    return render_template("admin/movie_edit.html", form=form, movie=movie)


# 电影删除
@admin.route("/movie/del/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def movie_del(id=None):
    movie = Movie.query.get_or_404(int(id))
    db.session.delete(movie)
    db.session.commit()

    flash("删除电影成功!", "ok")
    return redirect(url_for("admin.movie_list", page=1))


# 电影预告
@admin.route('/preview/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def preview_list(page=None):
    if page is None:
        page = 1
    page_data = Preview.query.order_by(Preview.addtime.desc()).paginate(page=page, per_page=10)

    return render_template("admin/preview_list.html", page_data=page_data)


# 添加预告
@admin.route('/preview/add/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def preview_add():
    form = PreviewForm()
    if form.validate_on_submit():
        data = form.data
        file_logo = secure_filename(form.logo.data.filename)
        if not os.path.exists(logo_path):
            os.makedirs(logo_path)
            os.chmod(logo_path, 6)
        logo = change_filename(file_logo)
        form.logo.data.save(logo_path + logo)
        preview = Preview(
            title=data.get("title"),
            logo=logo
        )
        db.session.add(preview)
        db.session.commit()
        flash("添加预告成功!", "ok")
        return redirect(url_for("admin.preview_add"))
    return render_template("admin/preview_add.html", form=form)


# 编辑预告
@admin.route("/preview/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def preview_edit(id=None):
    form = PreviewForm()
    form.logo.validators = []
    preview = Preview.query.get_or_404(int(id))
    if request.method == "GET":
        form.title.data = preview.title
    if form.validate_on_submit():
        data = form.data
        if form.logo.data.filename != "":
            file_logo = secure_filename(form.logo.data.filename)
            preview.logo = change_filename(file_logo)
            form.logo.data.save(logo_path + preview.logo)
        preview.title = data.get("title")
        db.session.add(preview)
        db.session.commit()
        flash("修改预告成功！", "ok")
        return redirect(url_for("admin.preview_edit", id=id))
    return render_template("admin/preview_edit.html", form=form, preview=preview)


# 删除预告
@admin.route("/preview/del/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def preview_del(id=None):
    preview = Preview.query.get_or_404(int(id))
    db.session.delete(preview)
    db.session.commit()

    flash("删除预告成功！", "ok")
    return redirect(url_for("admin.preview_list", page=1))


# 会员列表
@admin.route('/user/list/<int:page>/', methods=['GET'])
@admin_login_req
@admin_auth
def user_list(page=None):
    if page is None:
        page = 1
    page_data = User.query.order_by(User.addtime.asc()).paginate(page=page, per_page=3)
    return render_template("admin/user_list.html", page_data=page_data)


# 会员展示
@admin.route('/user/view/<int:id>/', methods=['GET'])
@admin_login_req
@admin_auth
def user_view(id=None):
    user = User.query.get_or_404(int(id))
    return render_template("admin/user_view.html", user=user)


# 会员删除
@admin.route("/user/del/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def user_del(id=None):
    user = User.query.get_or_404(int(id))
    db.session.delete(user)
    db.session.commit()
    flash("删除会员成功", "ok")
    return redirect(url_for('admin.user_list', page=1))


# 评论列表
@admin.route('/comment/list/<int:page>/', methods=['GET'])
@admin_login_req
@admin_auth
def comment_list(page=None):
    if page is None:
        page = 1
    page_data = Comment.query.join(Movie).join(User).filter(
        Movie.id == Comment.movie_id,
        User.id == Comment.user_id
    ).order_by(Comment.addtime).paginate(page=page, per_page=10)

    return render_template("admin/comment_list.html", page_data=page_data)


# 评论删除
@admin.route("/comment/del/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def comment_del(id=None):
    comment = Comment.query.get_or_404(int(id))
    db.session.delete(comment)
    db.session.commit()
    flash("删除评论成功", "ok")
    return redirect(url_for("admin.comment_list", page=1))


# 收藏列表
@admin.route('/moviecol/list/<int:page>/', methods=["GET"])
@admin_login_req
@admin_auth
def moviecol_list(page=None):
    if page is None:
        page = 1
    page_data = Moviecol.query.join(Movie).join(User).filter(
        Movie.id == Moviecol.movie_id,
        User.id == Moviecol.user_id
    ).order_by(Moviecol.addtime).paginate(page=page, per_page=10)
    return render_template("admin/moviecol_list.html", page_data=page_data)


# 收藏删除
@admin.route("/moviecol/del/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def moviecol_del(id=None):
    moviecol = Moviecol.query.get_or_404(int(id))
    db.session.delete(moviecol)
    db.session.commit()
    flash("删除收藏成功", "ok")
    return redirect(url_for("admin.moviecol_list", page=1))


# 用户操作日志
@admin.route('/oplog/list/<int:page>/', methods=['GET'])
@admin_login_req
@admin_auth
def oplog_list(page=None):
    if page is None:
        page = 1
    page_data = Oplog.query.join(Admin).filter(Admin.id == Oplog.admin_id).order_by(
        Oplog.addtime
    ).paginate(page=page, per_page=5)

    return render_template("admin/oplog_list.html", page_data=page_data)


# 管理员登录日志
@admin.route('/adminloginlog/list/<int:page>/', methods=['GET'])
@admin_login_req
@admin_auth
def adminloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = Adminlog.query.join(Admin).filter(Admin.id == Adminlog.admin_id).order_by(
        Adminlog.addtime
    ).paginate(page=page, per_page=5)
    print(page_data.__dict__)
    return render_template("admin/adminloginlog_list.html", page_data=page_data)


# 会员登录日志
@admin.route('/userloginlog/list/<int:page>/', methods=['GET'])
@admin_login_req
@admin_auth
def userloginlog_list(page=None):
    if page is None:
        page = 1
    page_data = Userlog.query.join(User).filter(User.id == Userlog.user_id).order_by(
        Userlog.id
    ).paginate(page=page, per_page=10)
    print(page_data)
    return render_template("admin/userloginlog_list.html", page_data=page_data)


# 权限列表
@admin.route('/auth/list/<int:page>/', methods=['GET'])
@admin_login_req
@admin_auth
def auth_list(page=None):
    if page is None:
        page = 1
    page_data = Auth.query.order_by(Auth.id).paginate(page=page, per_page=10)
    return render_template("admin/auth_list.html", page_data=page_data)


# 权限添加
@admin.route('/auth/add/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def auth_add():
    form = AuthForm()
    if form.validate_on_submit():
        data = form.data
        auth = Auth(
            name=data.get('name'),
            url=data.get('url'),
        )
        db.session.add(auth)
        db.session.commit()
        flash("添加权限成功！", "ok")
        return redirect(url_for("admin.auth_list", page=1))
    return render_template("admin/auth_add.html", form=form)


# 权限编辑
@admin.route("/auth/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def auth_edit(id=None):
    form = AuthForm()
    auth = Auth.query.get_or_404(id)
    if form.validate_on_submit():
        data = form.data
        auth.name = data.get("name")
        auth.url = data.get('url')
        db.session.add(auth)
        db.session.commit()
        flash("修改权限成功！", "ok")
        return redirect(url_for("admin.auth_list", page=1))
    return render_template("admin/auth_edit.html", form=form, auth=auth)


# 权限删除
@admin.route("/auth/del/<int:id>/", methods=["GET"])
@admin_login_req
@admin_auth
def auth_del(id=None):
    auth = Auth.query.filter_by(id=id).first_or_404()
    db.session.delete(auth)
    db.session.commit()
    flash("删除权限成功！", "ok")
    return redirect(url_for("admin.auth_list", page=1))


# 角色列表
@admin.route('/role/list/<int:page>/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_list(page=None):
    if page is None:
        page = 1
    page_data = Role.query.order_by(Role.id).paginate(page=page, per_page=10)
    return render_template("admin/role_list.html", page_data=page_data)


# 角色添加
@admin.route('/role/add/', methods=["GET", "POST"])
@admin_login_req
@admin_auth
def role_add():
    form = RoleForm()
    auth_lists = Auth.query.all()
    form.auths.choices = [(v.id, v.name) for v in auth_lists]
    if form.validate_on_submit():
        data = form.data
        role = Role(
            name=data.get("name"),
            auths=",".join(map(lambda v: str(v), data.get("auths")))
        )
        db.session.add(role)
        db.session.commit()
        flash("添加角色成功！", "ok")
        return redirect(url_for("admin.role_list", page=1))
    return render_template("admin/role_add.html", form=form)


# 角色编辑
@admin.route("/role/edit/<int:id>/", methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def role_edit(id=None):
    form = RoleForm()
    auth_lists = Auth.query.all()
    form.auths.choices = [(v.id, v.name) for v in auth_lists]
    role = Role.query.get_or_404(id)
    if request.method == 'GET':
        auths = role.auths
        form.auths.data = list(map(lambda v: int(v), auths.split(",")))
    if form.validate_on_submit():
        data = form.data
        role.name = data.get("name")
        role.auths = ",".join(map(lambda v: str(v), data.get('auths')))
        db.session.add(role)
        db.session.commit()
        flash("修改角色成功！", "ok")
    return render_template("admin/role_edit.html", form=form, role=role)


# 角色删除
@admin.route("/role/del/<int:id>/", methods=['GET'])
@admin_login_req
@admin_auth
def role_del(id=None):
    role = Role.query.filter_by(id=id).first_or_404()
    db.session.delete(role)
    db.session.commit()
    flash("角色删除成功！", "ok")
    return redirect(url_for("admin.role_list", page=1))


# 管理员表单
@admin.route('/admin/list/<int:page>/', methods=['GET'])
@admin_login_req
@admin_auth
def admin_list(page=None):
    if page is None:
        page = 1
    page_data = Admin.query.join(Role).filter(Role.id == Admin.role_id).order_by(
        Admin.id
    ).paginate(page=page, per_page=10)

    print("page_data:", page_data)
    return render_template("admin/admin_list.html", page_data=page_data)


# 添加管理员
@admin.route('/admin/add/', methods=['GET', 'POST'])
@admin_login_req
@admin_auth
def admin_add():
    form = AdminForm()
    role_lists = Role.query.all()
    form.role_id.choices = [(v.id, v.name) for v in role_lists]
    from werkzeug.security import generate_password_hash
    if form.validate_on_submit():
        data = form.data
        admin = Admin(
            name=data.get("name"),
            pwd=generate_password_hash(data.get('pwd')),
            role_id=data.get("role_id"),
            is_super=1,
        )
        db.session.add(admin)
        db.session.commit()
        flash("添加管理员成功！", "ok")
        return redirect(url_for('admin.admin_list', page=1))
    return render_template("admin/admin_add.html", form=form)




