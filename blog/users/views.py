from django.db import DatabaseError
from django.shortcuts import render
from django.http import HttpResponse
import re
from django.shortcuts import redirect
# Create your views here.
# 注册视图
from django.urls import reverse
from django.views import View

from users.models import User
from utils.response_code import RETCODE
import logging

logger = logging.getLogger('django')

from random import randint
from libs.yuntongxun.sms import CCP


class RegisterView(View):
    def get(self, request):
        return render(request, 'register.html')

    def post(self, request):
        """
        1.接受数据
        2.验证数据
            2.1参数是否齐全
            2.2手机号格式是否正确
            2.3密码是否符合格式
            2.4密码和确认密码是否一致
            2.5短信验证码是否和redis一致
        3.保存注册信息
        4.返回响应跳转指定页面
        :param request:
        :return:
        """
        # 1.接受数据
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')
        # 2.验证数据
        #     2.1参数是否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest("缺少必要参数")
        #     2.2手机号格式是否正确
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        #     2.3密码是否符合格式
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('请输入8-20位密码，密码是数字，字母')
        #     2.4密码和确认密码是否一致
        if password != password2:
            return HttpResponseBadRequest('两次密码不一致')
        #     2.5短信验证码是否和redis一致
        redis_conn = get_redis_connection('default')
        redis_sms_code = redis_conn.get('sms:%s' % mobile)
        if redis_sms_code is None:
            return HttpResponseBadRequest('短信验证码已过期')
        if smscode != redis_sms_code.decode():
            return HttpResponseBadRequest('短信验证码不一致')
        # 3.保存注册信息
        # create_user 可以使用系统方法对密码加密
        try:
            user = User.objects.create_user(username=mobile, mobile=mobile, password=password)
        except DatabaseError as e:
            logger.error(e)
            return HttpResponseBadRequest('注册失败')
        from django.contrib.auth import login
        login(request, user)

        # 4.返回响应跳转指定页面
        response = redirect(reverse('home:index'))
        # 暂时返回一个注册成功信息，后期再实现指定页面
        # return HttpResponse('注册成功，从定向到首页')

        # 设置cookie信息，方便首页中用户信息展示的判断和用户信息的展示
        response.set_cookie('is_login', True)
        response.set_cookie('username', user.username, max_age=7 * 24 * 3600)
        return response


from django.http.response import HttpResponseBadRequest, JsonResponse
from libs.captcha.captcha import captcha
from django_redis import get_redis_connection


class ImageCodeView(View):
    def get(self, request):
        """
        1.接收前端传递的uuid
        2.判断uuid是否获取到
        3.通过调用captcha 生成图片验证码 （图片二进制 图片内容）
        4.将图片内容保存到redis
            uuid作为key  图片内容作为value  同时设置时效
        5.图片二进制返回给前端
        :param request:
        :return:
        """
        # 1.接收前端传递的uuid
        uuid = request.GET.get('uuid')
        # 2.判断uuid是否获取到
        if uuid is None:
            return HttpResponseBadRequest("没有传递uuid")
        # 3.通过调用captcha 生成图片验证码 （图片二进制 图片内容）
        text, image = captcha.generate_captcha()
        # 4.将图片内容保存到redis
        #     uuid作为key  图片内容作为value  同时设置时效
        redis_conn = get_redis_connection('default')
        # key 设置为uuid
        # second 为过期秒数 300s 过期时间
        # value text
        redis_conn.setex('img:%s' % uuid, 300, text)
        # 5.图片二进制返回给前端
        return HttpResponse(image, content_type='image/jpeg')


class SmsCodeView(View):

    def get(self, request):
        """
        # 1.接受参数
        # 2.参数的验证
        #     2.1参数是否齐全
        #     2.2图片验证码的验证
        #         连接redis，获取redis中图片验证码
        #         判断图片验证码是否存在
        #         如果图片验证码未过期，获取到后就可以删除图片验证码
        #         比对图片验证码
        # 3.生成短信验证码
        # 4.短信验证码保存到redis中
        # 5.发送短信
        # 6.返回响应
        :param request:
        :return:
        """
        # 1.接受参数（查询字符串的形式传递过来）
        mobile = request.GET.get('mobile')
        image_code = request.GET.get('image_code')
        uuid = request.GET.get('uuid')
        # 2.参数的验证
        #     2.1参数是否齐全
        if not all([mobile, image_code, uuid]):
            return JsonResponse({'code': RETCODE.NECESSARYPARAMERR, 'errmsg': '缺少必要的参数'})
        #     2.2图片验证码的验证
        #         连接redis，获取redis中图片验证码
        redis_conn = get_redis_connection('default')
        redis_image_code = redis_conn.get('img:%s' % uuid)
        #         判断图片验证码是否存在
        if redis_image_code is None:
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图片验证码已过期'})
        #         如果图片验证码未过期，获取到后就可以删除图片验证码
        try:
            redis_conn.delete('img:%s' % uuid)
        except Exception as e:
            logger.error(e)
        #         比对图片验证码，注意大小写，redis数据是bytes类型
        if redis_image_code.decode().lower() != image_code.lower():
            return JsonResponse({'code': RETCODE.IMAGECODEERR, 'errmsg': '图片验证码错误'})
        # 3.生成短信验证码
        sms_code = '%06d' % randint(0, 999999)
        # 为了后期比对方便，将短信验证码记录到日志中
        logger.info(sms_code)
        # 4.短信验证码保存到redis中
        redis_conn.setex('sms:%s' % mobile, 300, sms_code)
        # 5.发送短信
        # 参数1：测试手机号
        # 参数2：模板内容列表：{1}短信验证码 {2}分钟有效
        # 参数3：模板
        CCP().send_template_sms(mobile, [sms_code, 5], 1)
        # 6.返回响应
        return JsonResponse({'code': RETCODE.OK, 'errmsg': '短信发送成功'})


class LoginView(View):

    def get(self, request):

        return render(request, 'login.html')

    def post(self, request):
        """
       1.接收参数
       2.参数的验证
           2.1验证手机号是否符合规则
           2.2验证密码是否符合规则
       3.用户认证登录
       4.状态保持
       5.根据用户选择的是否记录登录状态进行判断
       6.为了首页显示需要设置cookie信息
       7.返回响应
       :param request:
       :return:
       """
        # 1.接收参数
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        remember = request.POST.get('remember')
        # 2.参数的验证
        # 验证参数是否齐全
        if not all([mobile, password]):
            return HttpResponseBadRequest('缺少必传参数')
        #     2.1验证手机号是否符合规则
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        #     2.2验证密码是否符合规则
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('密码不符合规则')
        # 3.用户认证登录
        # 采用系统自带的认证方法进行认证
        # 如果用户名和密码正确，会返回user
        # 如果用户名和密码不正确，会返回None
        from django.contrib.auth import authenticate
        # 默认认证方法是针对username字段进行用户名判断
        # 当前判断信息是手机号，所以需要修改认证字段
        user = authenticate(mobile=mobile, password=password)
        if user is None:
            return HttpResponseBadRequest('用户名或密码错误')
        # 4.状态保持
        from django.contrib.auth import login
        login(request, user)
        # 5.根据用户选择的是否记录登录状态进行判断
        # 6.为了首页显示需要设置cookie信息

        # 根据next参数进行页面跳转
        next_page = request.GET.get('next')
        if next_page:
            response = redirect(next_page)
        else:
            response = redirect(reverse('home:index'))
        if remember != 'on':  # 没有记住用户信息
            # 浏览器关闭之后
            request.session.set_expiry(0)
            response.set_cookie('is_login', True)
            response.set_cookie('username', user.username, max_age=30 * 24 * 3600)
        else:  # 记住用户信息
            # 默认两周
            request.session.set_expiry(None)
            response.set_cookie('is_login', True, max_age=14 * 24 * 3600)
            response.set_cookie('username', user.username, max_age=30 * 24 * 3600)
        # 7.返回响应
        return response


from django.contrib.auth import logout


class LogoutView(View):

    def get(self, request):
        # 1.session数据的清除
        logout(request)
        # 2.删除部分cookie数据
        response = redirect(reverse('home:index'))
        response.delete_cookie('is_login')
        # 3.跳转到首页
        return response


class ForgetPasswordView(View):

    def get(self, request):

        return render(request, 'forget_password.html')

    def post(self, request):
        """
        1.接收数据
        2.数据验证
            2.1参数是否齐全
            2.2手机号是否符合规则
            2.3密码是否符合规则
            2.4判断确认密码和密码是否一致
            2.5判断短信验证码是否正确
        3.根据手机号进行用户信息查询
        4.如果手机号查询出用户信息，则修改
        5.如果手机号未查询出用户信息，则进行新用户创建
        6.页面跳转，跳转到登录页面
        7.返回响应
        :param request:
        :return:
        """
        # 1.接收数据
        mobile = request.POST.get('mobile')
        password = request.POST.get('password')
        password2 = request.POST.get('password2')
        smscode = request.POST.get('sms_code')
        # 2.数据验证
        #     2.1参数是否齐全
        if not all([mobile, password, password2, smscode]):
            return HttpResponseBadRequest('参数不全')
        #     2.2手机号是否符合规则
        if not re.match(r'^1[3-9]\d{9}$', mobile):
            return HttpResponseBadRequest('手机号不符合规则')
        #     2.3密码是否符合规则
        if not re.match(r'^[0-9A-Za-z]{8,20}$', password):
            return HttpResponseBadRequest('密码不符合规则')
        #     2.4判断确认密码和密码是否一致
        if password != password2:
            return HttpResponseBadRequest('密码不一致')
        #     2.5判断短信验证码是否正确
        redis_conn = get_redis_connection('default')
        sms_code_server = redis_conn.get('sms:%s' % mobile)
        if sms_code_server is None:
            return HttpResponseBadRequest('验证码已过期')
        if smscode != sms_code_server.decode():
            return HttpResponseBadRequest('短信验证码错误')
        # 3.根据手机号进行用户信息查询
        try:
            user = User.objects.get(mobile=mobile)
        except User.DoesNotExist:
            # 5.如果手机号未查询出用户信息，则进行新用户创建
            try:
                User.objects.create_user(username=mobile,
                                         mobile=mobile,
                                         password=password)
            except Exception:
                return HttpResponseBadRequest('修改失败，请稍后再试')
        else:
            # 4.如果手机号查询出用户信息，则修改
            user.set_password(password)
            # 注意 保存用户信息
            user.save()
        # 6.页面跳转，跳转到登录页面
        response = redirect(reverse('users:login'))
        # 7.返回响应
        return response


from django.contrib.auth.mixins import LoginRequiredMixin


# LoginRequiredMixin
# 如果用户未登录，会默认跳转
# 默认跳转链接是 accounts/login/?next=xxx
class UserCenterView(LoginRequiredMixin, View):

    def get(self, request):
        # 获得登录用户的信息
        user = request.user
        # 组织获取用户信息
        context = {
            'username': user.username,
            'mobile': user.mobile,
            'avatar': user.avatar.url if user.avatar else None,
            'user_desc': user.user_desc,
        }

        return render(request, 'center.html', context=context)

    def post(self, request):
        """
        # 1.接收参数
        # 2.参数保存
        # 3.更新cookie中的username
        # 4.刷新当前页面（重定向操作）
        # 5.返回响应
        :param request:
        :return:
        """
        # 1.接收参数
        user = request.user
        username = request.POST.get('username', user.username)
        user_desc = request.POST.get('desc', user.user_desc)
        avatar = request.FILES.get('avatar')
        # 2.参数保存
        try:
            user.username = username
            user.user_desc = user_desc
            if avatar:
                user.avatar = avatar
            user.save()
        except Exception as e:
            logger.error(e)
            return HttpResponseBadRequest('修改失败，请稍后再试')
        # 3.更新cookie中的username
        # 4.刷新当前页面（重定向操作）
        response = redirect(reverse('users:center'))
        response.set_cookie('username', user.username, max_age=14 * 3600 * 24)
        # 5.返回响应
        return response


class WriteBlogView(View):
    def get(self, request):
        return render(request, 'write_blog.html')
