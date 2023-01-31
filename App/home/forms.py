# -*- coding: utf-8 -*
# @Time    : 2022/2/10 15:06
# @Author  : liuy
# @File    : forms.py


from flask_wtf import FlaskForm
from wtforms.fields import StringField, PasswordField, SubmitField, FileField, TextAreaField, EmailField
from wtforms.validators import DataRequired, EqualTo, Email, Regexp, ValidationError
from App.models import User

# 登录表单
class LoginForm(FlaskForm):
    name = StringField(
        label="账号",
        validators=[
            DataRequired("请输入帐号！")    # 这个字段不能为空
        ],
        description="账号",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入帐号！"
        }
    )
    pwd = PasswordField(
        label="密码",
        validators=[
            DataRequired("请输入密码！")
        ],
        description="密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入密码！",
        }
    )
    submit = SubmitField(
        "登录",
        render_kw={
            "class": "btn btn-lg btn-primary btn-block"
        }
    )

    def validate_name(self, field):
        name = field.data
        user = User.query.filter_by(name=name).count()
        if user == 0:
            raise ValidationError("会员账号不存在！")

    def validata_pwd(self, field):
        pwd = field.data
        name = self.name.data
        user = User.query.filter_by(name=name).count()
        if not user.check_pwd(pwd):
            raise ValidationError("密码错误！")


# 注册表单
class RegistForm(FlaskForm):
    name = StringField(
        label="呢称",
        validators=[
            DataRequired("请输入呢称！")
        ],
        description="呢称",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入呢称！",
        }
    )
    email = EmailField(
        label="邮箱",
        validators=[
            DataRequired("请输入邮箱！"),
            # Email("邮箱格式不正确！"),
        ],
        description="邮箱",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入邮箱！"
        }
    )
    phone = StringField(
        label="手机号",
        validators=[
            DataRequired("请输入手机号！"),
            Regexp("1[34578]\\d{9}", message="输入的手机号格式不正确！"),
        ],
        description="手机号",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入手机号！"
        }
    )
    pwd = PasswordField(
        label="密码",
        validators=[
            DataRequired("请输入密码！")
        ],
        description="密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入密码！"
        }
    )
    repwd = PasswordField(
        label="确认密码",
        validators=[
            DataRequired("请输入确认密码！"),
            EqualTo("pwd", message="两次密码不一致！")
        ],
        description="确认密码",
        render_kw={
            "class": "form-control input-lg",
            "placeholder": "请输入确认密码！"
        }
    )
    submit = SubmitField(
        "注册",
        render_kw={
            "class": "btn btn-lg btn-success btn-block"
        }
    )

    def validate_name(self, field):               # 这是一个钩子函数  对用户名进行验证
        name = field.data                         # field.data 就是当前name从表单提交过来的值
        user = User.query.filter_by(name=name).count()   # 从数据库里面取值
        if user == 1:                             # 如果从数据库里取到了这个值。说明用户名存在
            raise ValidationError("呢称已经存在，请重新输入！")

    def validate_email(self, field):
        email = field.data
        user = User.query.filter_by(email=email).count()
        if user == 1:
            raise ValidationError("邮箱已经存在，请重新输入！")

    def validate_phone(self, field):
        phone = field.data
        user = User.query.filter_by(phone=phone).count()
        if user == 1:
            raise ValidationError("手机号已经存在，请重新输入！")


# 用户表
class UserdetailForm(FlaskForm):
    name = StringField(
        label="呢称",
        validators=[
            DataRequired("请输入呢称！")
        ],
        description="呢称",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入呢称！"
        }
    )
    email = StringField(
        label="邮箱",
        validators=[
            DataRequired("请输入邮箱！"),
            # Email("邮箱的格式不正确，请重新输入！")
        ],
        description="邮箱",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入邮箱！"
        }
    )
    phone = StringField(
        label="手机号",
        validators=[
            DataRequired("请输入手机号！"),
            Regexp("1[34578]\\d{9}", message="输入的手机号格式不正确！"),
        ],
        description="手机号",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入手机号！"
        }
    )
    face = FileField(
        label="头像",
        validators=[
            DataRequired("请上传头像！")
        ],
        description="头像"
    )
    info = TextAreaField(
        label="简介",
        validators=[
            DataRequired("请输入简介！")
        ],
        description="简介",
        render_kw={
            "class": "form-control",
            "rows": "10"
        }
    )
    submit = SubmitField(
        "保存修改",
        render_kw={
            "class": "btn btn-success",
        }
    )


class PwdForm(FlaskForm):
    old_pwd = PasswordField(
        label="旧密码",
        validators=[
            DataRequired("请输入旧密码!")
        ],
        description="旧密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入旧密码!"
        }
    ),
    new_pwd = PasswordField(
        label="新密码",
        validators=[
            DataRequired("请输入新密码!")
        ],
        description="新密码",
        render_kw={
            "class": "form-control",
            "placeholder": "请输入新密码!"
        }
    )
    submit = SubmitField(
        "修改密码",
        render_kw={
            "class": "btn btn-success"
        }
    )


# 评论表单
class CommentForm(FlaskForm):
    content = TextAreaField(
        label="内容",
        validators=[
            DataRequired("请输入内容！"),
        ],
        description="内容",
        render_kw={
            "id": "input_content",
            "class": "form-control",
            "rows": "10"
        }
    )
    submit = SubmitField(
        label='提交评论',
        render_kw={
            "class": "btn btn-success",
            "id": "btn-sub"
        }
    )