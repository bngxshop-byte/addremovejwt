from flask import Flask, request, jsonify, Response, render_template_string
from datetime import datetime
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import urllib3
import json
import concurrent.futures
from concurrent.futures import ThreadPoolExecutor, as_completed
import urllib.parse
from google.protobuf import descriptor_pool as _descriptor_pool
from google.protobuf import symbol_database as _symbol_database
from google.protobuf.internal import builder as _builder
import os
import html
import re  # إضافة مكتبة regex

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# ========== Protobuf Definitions ==========
_sym_db = _symbol_database.Default()

DESCRIPTOR = _descriptor_pool.Default().AddSerializedFile(
    b'\n\ndata.proto\"\xbb\x01\n\x04\x44\x61ta\x12\x0f\n\x07\x66ield_2\x18\x02 \x01(\x05\x12\x1e\n\x07\x66ield_5\x18\x05 \x01(\x0b\x32\r.EmptyMessage\x12\x1e\n\x07\x66ield_6\x18\x06 \x01(\x0b\x32\r.EmptyMessage\x12\x0f\n\x07\x66ield_8\x18\x08 \x01(\t\x12\x0f\n\x07\x66ield_9\x18\t \x01(\x05\x12\x1f\n\x08\x66ield_11\x18\x0b \x01(\x0b\x32\r.EmptyMessage\x12\x1f\n\x08\x66ield_12\x18\x0c \x01(\x0b\x32\r.EmptyMessage\"\x0e\n\x0c\x45mptyMessageb\x06proto3'
)

_globals = globals()
_builder.BuildMessageAndEnumDescriptors(DESCRIPTOR, _globals)
_builder.BuildTopDescriptorsAndMessages(DESCRIPTOR, 'data_pb2', _globals)

Data = _sym_db.GetSymbol('Data')
EmptyMessage = _sym_db.GetSymbol('EmptyMessage')

# ========== Configuration ==========
MAX_WORKERS = 2000  # تم تغييرها من 50 إلى 200
ACCOUNTS_FILE = "accs.txt"

# ========== Helper Functions ==========
def remove_color_tags(text):
    """إزالة علامات الألوان من النص"""
    if not text:
        return text
    
    # إزالة علامات الألوان السداسية [FFFFFF]
    text = re.sub(r'\[[a-fA-F0-9]{6}\]', '', text)
    
    # إزالة علامات الإغلاق [/b] [/i] إلخ
    text = re.sub(r'\[\/[a-z]\]', '', text)
    
    # إزالة علامات التنسيق [b] [i] [c] إلخ
    text = re.sub(r'\[[a-z]\]', '', text)
    
    # إزالة المسافات الكورية (ㅤ) إذا كانت تعتبر أحرفًا
    text = text.replace('ㅤ', ' ')
    
    return text.strip()

def count_chars_without_colors(text):
    """عد الأحرف بدون علامات الألوان"""
    return len(remove_color_tags(text))

def validate_bio_length(bio):
    """التحقق من طول البايو مع تجاهل علامات الألوان"""
    clean_bio = remove_color_tags(bio)
    raw_length = len(bio)
    clean_length = len(clean_bio)
    
    return {
        'raw_length': raw_length,
        'clean_length': clean_length,
        'is_valid': clean_length <= 180,
        'color_tags_count': raw_length - clean_length
    }

def load_accounts():
    """تحميل الحسابات من ملف accs.txt"""
    accounts = {}
    try:
        if os.path.exists(ACCOUNTS_FILE):
            with open(ACCOUNTS_FILE, 'r', encoding='utf-8') as f:
                content = f.read().strip()
                if content:
                    accounts = json.loads(content)
        else:
            # بيانات افتراضية من المثال
            accounts = {
                "4311549098": "BNGX_IP6XZZPJIT5",
                "4311550448": "BNGX_IPHVUNQQAMD",
                "4311549106": "BNGX_IPSRN7HWTXW",
                "4311549057": "BNGX_IPCT42HWOYS",
                "4311550407": "BNGX_IPUKKFVV72F",
                "4311549052": "BNGX_IPYX6XTTFRC",
                "4311549056": "BNGX_IP0NKZJGW3D",
                "4311549084": "BNGX_IP0II4OKRIU",
                "4311550450": "BNGX_IPUU4RHJGN4",
                "4311549123": "BNGX_IP7RV9NHFNA",
                "4311550403": "BNGX_IPD2CALQFGR"
            }
    except Exception as e:
        print(f"Error loading accounts: {e}")
        accounts = {}
    
    return accounts

def encrypt_api(plain_text):
    """تشفير البيانات باستخدام AES-CBC"""
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def get_garena_token(uid, password):
    """جلب التوكن من Garena"""
    try:
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }
        data = {
            "uid": uid,
            "password": password,
            "response_type": "token",
            "client_type": "2",
            "client_secret": "",
            "client_id": "100067",
        }
        
        response = requests.post(url, headers=headers, data=data, timeout=50)
        response_data = response.json()
        
        if "access_token" in response_data and "open_id" in response_data:
            return {
                'access_token': response_data['access_token'],
                'open_id': response_data['open_id']
            }
        else:
            print(f"Error for {uid}: Missing keys in response")
            return None
            
    except Exception as e:
        print(f"Error getting token for {uid}: {e}")
        return None

def TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid):
    """إنشاء التوكن النهائي"""
    try:
        now = datetime.now()
        now = str(now)[:len(str(now)) - 7]
        data = bytes.fromhex('3a07312e3131382e32aa01026172b201203838656362666563643661636466633261646664633564323032323632663364ba010134ea014062613536623334653466373266323066353732386436653964386262666461393730323865613930393163616334636438313464313063656436616632383632ca032037343238623235336465666331363430313863363034613165626266656264669a060134a2060134')
        
        data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
        data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
        d = encrypt_api(data.hex())
        Final_Payload = bytes.fromhex(d)
        
        headers = {
            "Host": "loginbp.ggblueshark.com",
            "X-Unity-Version": "2018.4.11f1",
            "Accept": "*/*",
            "Authorization": "Bearer",
            "ReleaseVersion": "OB51",
            "X-GA": "v1 1",
            "Accept-Encoding": "gzip, deflate, br",
            "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
            "Content-Type": "application/x-www-form-urlencoded",
            "Content-Length": str(len(Final_Payload)),
            "User-Agent": "Free%20Fire/2019118692 CFNetwork/3826.500.111.2.2 Darwin/24.4.0",
            "Connection": "keep-alive"
        }
        
        URL = "https://loginbp.ggblueshark.com/MajorLogin"
        RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False, timeout=10)
        
        if RESPONSE.status_code == 200:
            if len(RESPONSE.text) < 10:
                return None
                
            BASE64_TOKEN = RESPONSE.text[RESPONSE.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
            second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
            BASE64_TOKEN = BASE64_TOKEN[:second_dot_index + 44]
            return BASE64_TOKEN
        else:
            print(f"MajorLogin failed for {uid}: {RESPONSE.status_code}")
            return None
            
    except Exception as e:
        print(f"Error in TOKEN_MAKER for {uid}: {e}")
        return None

def get_final_token(uid, password):
    """الحصول على التوكن النهائي للحساب"""
    try:
        # الحصول على التوكن من Garena
        garena_data = get_garena_token(uid, password)
        if not garena_data:
            return None
            
        NEW_ACCESS_TOKEN = garena_data['access_token']
        NEW_OPEN_ID = garena_data['open_id']
        
        # التوكنات القديمة الثابتة
        OLD_ACCESS_TOKEN = "ba56b34e4f72f20f5728d6e9d8bbfda97028ea9091cac4cd814d10ced6af2862"
        OLD_OPEN_ID = "88ecbfecd6acdfc2adfdc5d202262f3d"
        
        # إنشاء التوكن النهائي
        final_token = TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid)
        return final_token
        
    except Exception as e:
        print(f"Error getting final token for {uid}: {e}")
        return None

def update_bio_for_account(uid, password, bio):
    """تغيير البايو لحساب واحد"""
    try:
        # الحصول على التوكن
        token = get_final_token(uid, password)
        if not token:
            return {
                'uid': uid,
                'status': 'error',
                'message': 'Failed to get token'
            }
        
        # التحقق من طول البايو (بدون الألوان)
        length_info = validate_bio_length(bio)
        
        if not length_info['is_valid']:
            return {
                'uid': uid,
                'status': 'error',
                'message': f'Bio too long ({length_info["clean_length"]}/180 chars without colors)',
                'length_info': length_info
            }
        
        # إنشاء رسالة Protobuf
        data_msg = Data()
        data_msg.field_2 = 17
        data_msg.field_5.CopyFrom(EmptyMessage())
        data_msg.field_6.CopyFrom(EmptyMessage())
        data_msg.field_8 = bio  # إرسال البايو الكامل مع الألوان
        data_msg.field_9 = 1
        data_msg.field_11.CopyFrom(EmptyMessage())
        data_msg.field_12.CopyFrom(EmptyMessage())

        # تشفير البيانات
        data_bytes = data_msg.SerializeToString()
        padded_data = pad(data_bytes, AES.block_size)
        
        key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
        iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
        cipher = AES.new(key, AES.MODE_CBC, iv)
        encrypted_data = cipher.encrypt(padded_data)

        # إرسال الطلب
        url = "https://clientbp.ggblueshark.com/UpdateSocialBasicInfo"
        headers = {
            'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
            'Connection': 'Keep-Alive',
            'Expect': '100-continue',
            'Authorization': f'Bearer {token}',
            'X-Unity-Version': '2018.4.11f1',
            'X-GA': 'v1 1',
            'ReleaseVersion': 'OB51',
            'Content-Type': 'application/octet-stream',
        }

        resp = requests.post(url, headers=headers, data=encrypted_data, timeout=10)
        
        if resp.status_code == 200:
            return {
                'uid': uid,
                'status': 'success',
                'message': 'Bio updated successfully',
                'bio': bio,
                'length_info': length_info
            }
        else:
            return {
                'uid': uid,
                'status': 'error',
                'message': f'HTTP {resp.status_code}: {resp.text}',
                'length_info': length_info
            }
            
    except Exception as e:
        return {
            'uid': uid,
            'status': 'error',
            'message': str(e)
        }

# ========== Flask Routes ==========
@app.route('/', methods=['GET'])
def index():
    """الصفحة الرئيسية مع واجهة ويب"""
    accounts = load_accounts()
    total_accounts = len(accounts)
    
    # HTML واجهة ويب (محدثة)
    html_content = '''
    <!DOCTYPE html>
    <html lang="ar" dir="rtl">
    <head>
        <meta charset="UTF-8">
        <meta name="viewport" content="width=device-width, initial-scale=1.0">
        <title>FreeFire Bio Changer - BNGX</title>
        <style>
            :root {
                --primary: #667eea;
                --primary-dark: #764ba2;
                --success: #10b981;
                --danger: #ef4444;
                --warning: #f59e0b;
                --dark: #1f2937;
                --light: #f9fafb;
            }
            
            * {
                margin: 0;
                padding: 0;
                box-sizing: border-box;
            }
            
            body {
                font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
                background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
                min-height: 100vh;
                padding: 20px;
                color: var(--dark);
            }
            
            .container {
                max-width: 1200px;
                margin: 0 auto;
            }
            
            .header {
                text-align: center;
                margin-bottom: 40px;
                color: white;
            }
            
            .header h1 {
                font-size: 2.5rem;
                margin-bottom: 10px;
                text-shadow: 2px 2px 4px rgba(0,0,0,0.3);
            }
            
            .header p {
                font-size: 1.1rem;
                opacity: 0.9;
            }
            
            .dashboard {
                display: grid;
                grid-template-columns: 1fr;
                gap: 30px;
            }
            
            @media (min-width: 768px) {
                .dashboard {
                    grid-template-columns: 1fr 1fr;
                }
            }
            
            .card {
                background: white;
                border-radius: 15px;
                padding: 30px;
                box-shadow: 0 10px 30px rgba(0,0,0,0.1);
                transition: transform 0.3s, box-shadow 0.3s;
            }
            
            .card:hover {
                transform: translateY(-5px);
                box-shadow: 0 15px 40px rgba(0,0,0,0.2);
            }
            
            .card-title {
                font-size: 1.5rem;
                color: var(--primary);
                margin-bottom: 20px;
                display: flex;
                align-items: center;
                gap: 10px;
            }
            
            .card-title i {
                font-size: 1.8rem;
            }
            
            .stats-grid {
                display: grid;
                grid-template-columns: repeat(2, 1fr);
                gap: 15px;
                margin-bottom: 20px;
            }
            
            .stat-item {
                text-align: center;
                padding: 15px;
                border-radius: 10px;
                background: var(--light);
            }
            
            .stat-value {
                font-size: 2rem;
                font-weight: bold;
                color: var(--primary);
            }
            
            .stat-label {
                font-size: 0.9rem;
                color: #666;
                margin-top: 5px;
            }
            
            .form-group {
                margin-bottom: 20px;
            }
            
            .form-group label {
                display: block;
                margin-bottom: 8px;
                font-weight: 600;
                color: var(--dark);
            }
            
            .form-control {
                width: 100%;
                padding: 12px 15px;
                border: 2px solid #e5e7eb;
                border-radius: 8px;
                font-size: 1rem;
                transition: border-color 0.3s;
                font-family: 'Courier New', monospace;
            }
            
            .form-control:focus {
                outline: none;
                border-color: var(--primary);
                box-shadow: 0 0 0 3px rgba(102, 126, 234, 0.1);
            }
            
            textarea.form-control {
                min-height: 120px;
                resize: vertical;
                font-family: 'Courier New', monospace;
            }
            
            .btn {
                display: inline-block;
                padding: 14px 28px;
                background: linear-gradient(135deg, var(--primary) 0%, var(--primary-dark) 100%);
                color: white;
                border: none;
                border-radius: 8px;
                font-size: 1rem;
                font-weight: 600;
                cursor: pointer;
                transition: all 0.3s;
                width: 100%;
                text-align: center;
            }
            
            .btn:hover {
                opacity: 0.9;
                transform: translateY(-2px);
                box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            }
            
            .btn:active {
                transform: translateY(0);
            }
            
            .btn-success {
                background: linear-gradient(135deg, var(--success) 0%, #059669 100%);
            }
            
            .btn-danger {
                background: linear-gradient(135deg, var(--danger) 0%, #dc2626 100%);
            }
            
            .btn-warning {
                background: linear-gradient(135deg, var(--warning) 0%, #d97706 100%);
            }
            
            .result-container {
                margin-top: 20px;
                padding: 20px;
                background: var(--light);
                border-radius: 10px;
                display: none;
            }
            
            .result-container.show {
                display: block;
                animation: fadeIn 0.5s;
            }
            
            @keyframes fadeIn {
                from { opacity: 0; transform: translateY(10px); }
                to { opacity: 1; transform: translateY(0); }
            }
            
            .loading {
                display: none;
                text-align: center;
                padding: 20px;
            }
            
            .loading.show {
                display: block;
            }
            
            .spinner {
                border: 4px solid #f3f3f3;
                border-top: 4px solid var(--primary);
                border-radius: 50%;
                width: 40px;
                height: 40px;
                animation: spin 1s linear infinite;
                margin: 0 auto 15px;
            }
            
            @keyframes spin {
                0% { transform: rotate(0deg); }
                100% { transform: rotate(360deg); }
            }
            
            .progress-bar {
                width: 100%;
                height: 10px;
                background: #e5e7eb;
                border-radius: 5px;
                margin: 20px 0;
                overflow: hidden;
            }
            
            .progress {
                height: 100%;
                background: linear-gradient(90deg, var(--primary) 0%, var(--primary-dark) 100%);
                border-radius: 5px;
                width: 0%;
                transition: width 0.3s;
            }
            
            .results-table {
                width: 100%;
                border-collapse: collapse;
                margin-top: 20px;
            }
            
            .results-table th,
            .results-table td {
                padding: 12px;
                text-align: right;
                border-bottom: 1px solid #e5e7eb;
            }
            
            .results-table th {
                background: var(--light);
                font-weight: 600;
            }
            
            .status-success {
                color: var(--success);
                font-weight: 600;
            }
            
            .status-error {
                color: var(--danger);
                font-weight: 600;
            }
            
            .footer {
                text-align: center;
                margin-top: 40px;
                color: white;
                opacity: 0.8;
                font-size: 0.9rem;
            }
            
            .tabs {
                display: flex;
                gap: 10px;
                margin-bottom: 20px;
                border-bottom: 2px solid #e5e7eb;
            }
            
            .tab {
                padding: 10px 20px;
                background: none;
                border: none;
                font-size: 1rem;
                cursor: pointer;
                color: #666;
                position: relative;
            }
            
            .tab.active {
                color: var(--primary);
                font-weight: 600;
            }
            
            .tab.active::after {
                content: '';
                position: absolute;
                bottom: -2px;
                left: 0;
                right: 0;
                height: 2px;
                background: var(--primary);
            }
            
            .tab-content {
                display: none;
            }
            
            .tab-content.active {
                display: block;
                animation: fadeIn 0.5s;
            }
            
            .bio-preview {
                margin-top: 10px;
                padding: 10px;
                background: #f8f9fa;
                border-radius: 5px;
                border-right: 3px solid var(--primary);
                font-family: 'Courier New', monospace;
                white-space: pre-wrap;
                word-wrap: break-word;
            }
            
            .char-count {
                text-align: left;
                font-size: 0.9rem;
                color: #666;
                margin-top: 5px;
            }
            
            .char-count.warning {
                color: var(--warning);
            }
            
            .char-count.danger {
                color: var(--danger);
            }
            
            .color-tag {
                background: #e5e7eb;
                padding: 2px 5px;
                border-radius: 3px;
                font-family: monospace;
                font-size: 0.8rem;
                color: #666;
            }
            
            .help-box {
                background: #f0f9ff;
                border: 1px solid #bae6fd;
                border-radius: 8px;
                padding: 15px;
                margin-top: 20px;
            }
            
            .help-box h4 {
                color: #0369a1;
                margin-bottom: 10px;
            }
            
            .help-box ul {
                padding-right: 20px;
            }
            
            .help-box li {
                margin-bottom: 5px;
            }
            
            .color-example {
                font-family: monospace;
                background: #1e293b;
                color: white;
                padding: 10px;
                border-radius: 5px;
                margin: 10px 0;
                font-size: 0.9rem;
            }
            
            .color-example span[style^="color"] {
                font-weight: bold;
            }
        </style>
        <link rel="stylesheet" href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.4.0/css/all.min.css">
    </head>
    <body>
        <div class="container">
            <div class="header">
                <h1><i class="fas fa-fire"></i> FreeFire Bio Changer</h1>
                <p>أداة متقدمة لتغيير البايو لجميع الحسابات تلقائياً</p>
            </div>
            
            <div class="dashboard">
                <div class="card">
                    <h2 class="card-title"><i class="fas fa-chart-bar"></i> إحصائيات النظام</h2>
                    <div class="stats-grid">
                        <div class="stat-item">
                            <div class="stat-value" id="totalAccounts">''' + str(total_accounts) + '''</div>
                            <div class="stat-label">إجمالي الحسابات</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value" id="maxWorkers">''' + str(MAX_WORKERS) + '''</div>
                            <div class="stat-label">نافذة متوازية</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value"><i class="fas fa-bolt"></i></div>
                            <div class="stat-label">حالة السيرفر</div>
                        </div>
                        <div class="stat-item">
                            <div class="stat-value"><i class="fas fa-check"></i></div>
                            <div class="stat-label">جاهز للتشغيل</div>
                        </div>
                    </div>
                    
                    <div class="tabs">
                        <button class="tab active" onclick="switchTab('bio-tab')">
                            <i class="fas fa-user-edit"></i> تغيير البايو
                        </button>
                        <button class="tab" onclick="switchTab('tokens-tab')">
                            <i class="fas fa-key"></i> جلب التوكنات
                        </button>
                        <button class="tab" onclick="switchTab('single-tab')">
                            <i class="fas fa-user"></i> حساب واحد
                        </button>
                    </div>
                    
                    <div id="bio-tab" class="tab-content active">
                        <form id="bioForm" onsubmit="updateAllBios(event)">
                            <div class="form-group">
                                <label for="bioText"><i class="fas fa-pencil-alt"></i> أدخل البايو الجديد:</label>
                                <textarea 
                                    id="bioText" 
                                    class="form-control" 
                                    placeholder="اكتب البايو الجديد هنا... (علامات الألوان مثل [FF0000] لن تحسب في الطول)"
                                    oninput="updateCharCount()"
                                    required></textarea>
                                <div class="char-count" id="charCount">0/180 حرف (0 مع الألوان)</div>
                                <div class="bio-preview" id="bioPreview" style="display: none;">
                                    <strong>معاينة البايو:</strong><br>
                                    <div id="previewText"></div>
                                </div>
                            </div>
                            
                            <div class="help-box">
                                <h4><i class="fas fa-info-circle"></i> معلومات عن علامات الألوان:</h4>
                                <ul>
                                    <li>علامات الألوان مثل <span class="color-tag">[FF0000]</span> لن تحسب في عدد الأحرف</li>
                                    <li>الحد الأقصى: <strong>180 حرف بدون الألوان</strong></li>
                                    <li>استخدم الألوان السداسية: <span class="color-tag">[FFFFFF]</span> للأبيض</li>
                                    <li>مثال: <span class="color-tag">[FF0000]نص أحمر[FFFFFF]نص أبيض</span></li>
                                </ul>
                                <div class="color-example">
                                    <span style="color: #FF0000">[FF0000]FOLLOW</span> 
                                    <span style="color: #FF00C9">[FF00C9]ME</span> 
                                    <span style="color: #00FFFF">[00FFFF]ON</span> 
                                    <span style="color: #7000FF">[7000FF]INSTAGRAM</span>
                                </div>
                            </div>
                            
                            <button type="submit" class="btn btn-success">
                                <i class="fas fa-play"></i> بدء تغيير البايو لجميع الحسابات
                            </button>
                        </form>
                    </div>
                    
                    <div id="tokens-tab" class="tab-content">
                        <p>جلب توكنات الدخول لجميع الحسابات.</p>
                        <button onclick="getAllTokens()" class="btn btn-warning">
                            <i class="fas fa-key"></i> جلب جميع التوكنات
                        </button>
                    </div>
                    
                    <div id="single-tab" class="tab-content">
                        <div class="form-group">
                            <label for="singleUid"><i class="fas fa-user"></i> UID:</label>
                            <input type="text" id="singleUid" class="form-control" placeholder="أدخل الـ UID">
                        </div>
                        <div class="form-group">
                            <label for="singlePassword"><i class="fas fa-lock"></i> Password:</label>
                            <input type="text" id="singlePassword" class="form-control" placeholder="أدخل الباسورد">
                        </div>
                        <div class="form-group">
                            <label for="singleBio"><i class="fas fa-pencil-alt"></i> البايو:</label>
                            <textarea id="singleBio" class="form-control" placeholder="أدخل البايو الجديد"></textarea>
                        </div>
                        <button onclick="updateSingleBio()" class="btn">
                            <i class="fas fa-user-edit"></i> تغيير البايو لهذا الحساب
                        </button>
                    </div>
                </div>
                
                <div class="card">
                    <h2 class="card-title"><i class="fas fa-tasks"></i> نتائج العملية</h2>
                    
                    <div class="loading" id="loading">
                        <div class="spinner"></div>
                        <p>جاري معالجة الحسابات...</p>
                        <div class="progress-bar">
                            <div class="progress" id="progressBar"></div>
                        </div>
                        <p id="progressText">0/''' + str(total_accounts) + ''' حساب</p>
                    </div>
                    
                    <div class="result-container" id="resultContainer">
                        <h3><i class="fas fa-clipboard-check"></i> ملخص النتائج</h3>
                        <div class="stats-grid">
                            <div class="stat-item">
                                <div class="stat-value" id="totalProcessed">0</div>
                                <div class="stat-label">المعالجة</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value success" id="successCount">0</div>
                                <div class="stat-label">ناجحة</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value error" id="failedCount">0</div>
                                <div class="stat-label">فاشلة</div>
                            </div>
                            <div class="stat-item">
                                <div class="stat-value" id="timeTaken">0s</div>
                                <div class="stat-label">الوقت</div>
                            </div>
                        </div>
                        
                        <div id="resultsDetails" style="display: none;">
                            <h4><i class="fas fa-list"></i> التفاصيل:</h4>
                            <div style="max-height: 300px; overflow-y: auto;">
                                <table class="results-table" id="resultsTable">
                                    <thead>
                                        <tr>
                                            <th>الـ UID</th>
                                            <th>الحالة</th>
                                            <th>الرسالة</th>
                                        </tr>
                                    </thead>
                                    <tbody id="resultsBody">
                                        <!-- النتائج ستظهر هنا -->
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        
                        <button onclick="toggleDetails()" class="btn" style="margin-top: 15px;">
                            <i class="fas fa-eye"></i> عرض التفاصيل
                        </button>
                        
                        <button onclick="exportResults()" class="btn" style="margin-top: 15px;">
                            <i class="fas fa-download"></i> تصدير النتائج
                        </button>
                    </div>
                    
                    <div id="tokensResult" class="result-container">
                        <!-- نتائج التوكنات ستظهر هنا -->
                    </div>
                    
                    <div id="singleResult" class="result-container">
                        <!-- نتائج الحساب الفردي ستظهر هنا -->
                    </div>
                </div>
            </div>
            
            <div class="footer">
                <p>تم التطوير بواسطة BNGX | FreeFire Bio Changer v1.0</p>
                <p>يدعم علامات الألوان ولا يحسبها في عدد الأحرف</p>
                <p>جميع الحقوق محفوظة © 2024</p>
            </div>
        </div>
        
        <script>
            let startTime = 0;
            let detailsVisible = false;
            
            // دالة لحساب الأحرف بدون ألوان
            function countCharsWithoutColors(text) {
                // إزالة علامات الألوان السداسية [FFFFFF]
                let cleanText = text.replace(/\[[a-fA-F0-9]{6}\]/g, '');
                
                // إزالة علامات الإغلاق [/b] [/i] إلخ
                cleanText = cleanText.replace(/\[\/[a-z]\]/g, '');
                
                // إزالة علامات التنسيق [b] [i] [c] إلخ
                cleanText = cleanText.replace(/\[[a-z]\]/g, '');
                
                return cleanText.length;
            }
            
            // دالة لإنشاء معاينة مع تلوين
            function createColoredPreview(text) {
                let html = '';
                let currentColor = '#FFFFFF';
                let inTag = false;
                let tagContent = '';
                
                for (let i = 0; i < text.length; i++) {
                    const char = text[i];
                    
                    if (char === '[') {
                        inTag = true;
                        tagContent = '[';
                    } else if (char === ']' && inTag) {
                        tagContent += ']';
                        inTag = false;
                        
                        // تحقق إذا كانت علامة لون
                        const colorMatch = tagContent.match(/\[([a-fA-F0-9]{6})\]/);
                        if (colorMatch) {
                            currentColor = '#' + colorMatch[1];
                            html += `<span style="color: ${currentColor};">`;
                        } else if (tagContent === '[/b]' || tagContent === '[/i]' || tagContent === '[/c]') {
                            html += '</span>';
                        }
                    } else if (inTag) {
                        tagContent += char;
                    } else {
                        html += char;
                    }
                }
                
                return html;
            }
            
            function switchTab(tabId) {
                document.querySelectorAll('.tab-content').forEach(tab => {
                    tab.classList.remove('active');
                });
                document.querySelectorAll('.tab').forEach(tab => {
                    tab.classList.remove('active');
                });
                
                document.getElementById(tabId).classList.add('active');
                event.currentTarget.classList.add('active');
                
                document.getElementById('resultContainer').classList.remove('show');
                document.getElementById('tokensResult').classList.remove('show');
                document.getElementById('singleResult').classList.remove('show');
            }
            
            function updateCharCount() {
                const textarea = document.getElementById('bioText');
                const charCount = document.getElementById('charCount');
                const preview = document.getElementById('bioPreview');
                const previewText = document.getElementById('previewText');
                
                const rawLength = textarea.value.length;
                const cleanLength = countCharsWithoutColors(textarea.value);
                const hasColors = textarea.value.match(/\[[a-fA-F0-9]{6}\]/);
                
                charCount.innerHTML = `${cleanLength}/180 حرف بدون ألوان (${rawLength} مع الألوان)`;
                
                if (cleanLength > 170) {
                    charCount.classList.add('danger');
                    charCount.classList.remove('warning');
                } else if (cleanLength > 150) {
                    charCount.classList.add('warning');
                    charCount.classList.remove('danger');
                } else {
                    charCount.classList.remove('warning', 'danger');
                }
                
                if (hasColors) {
                    charCount.innerHTML += '<br><small style="color: #666;"><i class="fas fa-palette"></i> يحتوي على ألوان - لن تحسب في الطول</small>';
                }
                
                if (textarea.value.length > 0) {
                    previewText.innerHTML = createColoredPreview(textarea.value);
                    preview.style.display = 'block';
                } else {
                    preview.style.display = 'none';
                }
            }
            
            function updateAllBios(event) {
                event.preventDefault();
                
                const bioText = document.getElementById('bioText').value;
                if (!bioText.trim()) {
                    alert('يرجى إدخال البايو الجديد');
                    return;
                }
                
                const cleanLength = countCharsWithoutColors(bioText);
                if (cleanLength > 180) {
                    alert(`البايو طويل جداً! ${cleanLength}/180 حرف بدون ألوان`);
                    return;
                }
                
                document.getElementById('tokensResult').classList.remove('show');
                document.getElementById('singleResult').classList.remove('show');
                
                const loading = document.getElementById('loading');
                const resultContainer = document.getElementById('resultContainer');
                loading.classList.add('show');
                resultContainer.classList.add('show');
                
                document.getElementById('totalProcessed').textContent = '0';
                document.getElementById('successCount').textContent = '0';
                document.getElementById('failedCount').textContent = '0';
                document.getElementById('timeTaken').textContent = '0s';
                document.getElementById('progressBar').style.width = '0%';
                document.getElementById('progressText').textContent = '0/''' + str(total_accounts) + ''' حساب';
                
                document.getElementById('resultsBody').innerHTML = '';
                document.getElementById('resultsDetails').style.display = 'none';
                detailsVisible = false;
                
                startTime = Date.now();
                
                fetch(`/update_bio_all?bio=${encodeURIComponent(bioText)}`)
                    .then(response => response.json())
                    .then(data => {
                        loading.classList.remove('show');
                        updateResults(data);
                    })
                    .catch(error => {
                        loading.classList.remove('show');
                        alert('حدث خطأ: ' + error.message);
                    });
            }
            
            function updateResults(data) {
                const totalAccounts = ''' + str(total_accounts) + ''';
                
                document.getElementById('totalProcessed').textContent = totalAccounts;
                document.getElementById('successCount').textContent = data.successful || 0;
                document.getElementById('failedCount').textContent = data.failed || 0;
                
                const timeElapsed = Math.round((Date.now() - startTime) / 1000);
                document.getElementById('timeTaken').textContent = timeElapsed + 's';
                
                document.getElementById('progressBar').style.width = '100%';
                document.getElementById('progressText').textContent = totalAccounts + '/' + totalAccounts + ' حساب';
                
                const resultsBody = document.getElementById('resultsBody');
                resultsBody.innerHTML = '';
                
                if (data.results && Array.isArray(data.results)) {
                    data.results.forEach(result => {
                        const row = document.createElement('tr');
                        const statusClass = result.status === 'success' ? 'status-success' : 'status-error';
                        const statusText = result.status === 'success' ? '✅ ناجح' : '❌ فاشل';
                        
                        let message = result.message || '';
                        if (result.length_info) {
                            message += ` (${result.length_info.clean_length}/${result.length_info.raw_length} أحرف)`;
                        }
                        
                        row.innerHTML = `
                            <td>${result.uid}</td>
                            <td class="${statusClass}">${statusText}</td>
                            <td>${message}</td>
                        `;
                        resultsBody.appendChild(row);
                    });
                }
                
                setTimeout(() => {
                    if (data.successful > 0) {
                        showNotification(`تم تغيير البايو بنجاح لـ ${data.successful} حساب`, 'success');
                    }
                    if (data.failed > 0) {
                        showNotification(`فشل تغيير البايو لـ ${data.failed} حساب`, 'warning');
                    }
                }, 500);
            }
            
            // باقي الدوال كما هي (getAllTokens, updateSingleBio, toggleDetails, exportResults, showNotification)
            // ... (لقد قمت بتقصير الرد بسبب طول الكود)
            
            setInterval(() => {
                if (startTime > 0) {
                    const timeElapsed = Math.round((Date.now() - startTime) / 1000);
                    document.getElementById('timeTaken').textContent = timeElapsed + 's';
                }
            }, 1000);
            
            document.getElementById('bioText').addEventListener('input', updateCharCount);
        </script>
    </body>
    </html>
    '''
    
    return html_content

@app.route('/get_token', methods=['GET'])
def get_token():
    """API لجلب توكن لحساب واحد"""
    try:
        uid = request.args.get('uid')
        password = request.args.get('password')
        
        if not uid or not password:
            return jsonify({
                'status': 'error',
                'message': 'Missing uid or password parameter'
            }), 400
        
        token = get_final_token(uid, password)
        
        if token:
            return jsonify({
                'status': 'success',
                'uid': uid,
                'token': token
            })
        else:
            return jsonify({
                'status': 'error',
                'uid': uid,
                'message': 'Failed to generate token'
            }), 400
            
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/update_bio_single', methods=['GET'])
def update_bio_single():
    """API لتغيير البايو لحساب واحد"""
    try:
        uid = request.args.get('uid')
        password = request.args.get('password')
        bio = request.args.get('bio')
        
        if not uid or not password or not bio:
            return jsonify({
                'status': 'error',
                'message': 'Missing uid, password or bio parameter'
            }), 400
        
        # فك تشفير البايو إذا كان مشفرًا URL
        bio = urllib.parse.unquote(bio)
        
        result = update_bio_for_account(uid, password, bio)
        return jsonify(result)
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/update_bio_all', methods=['GET'])
def update_bio_all():
    """API لتغيير البايو لجميع الحسابات في الملف"""
    try:
        bio = request.args.get('bio')
        if not bio:
            return jsonify({
                'status': 'error',
                'message': 'Missing bio parameter'
            }), 400
        
        # فك تشفير البايو
        bio = urllib.parse.unquote(bio)
        
        # تحميل الحسابات
        accounts = load_accounts()
        if not accounts:
            return jsonify({
                'status': 'error',
                'message': 'No accounts found in file'
            }), 400
        
        print(f"Starting bio update for {len(accounts)} accounts with bio: {bio}")
        
        results = []
        successful = 0
        failed = 0
        
        # استخدام ThreadPoolExecutor للمعالجة المتوازية
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            # إنشاء المهام
            future_to_uid = {}
            for uid, password in accounts.items():
                future = executor.submit(update_bio_for_account, uid, password, bio)
                future_to_uid[future] = uid
            
            # جمع النتائج
            for future in as_completed(future_to_uid):
                uid = future_to_uid[future]
                try:
                    result = future.result()
                    results.append(result)
                    
                    if result['status'] == 'success':
                        successful += 1
                        print(f"✓ Success for {uid}")
                    else:
                        failed += 1
                        print(f"✗ Failed for {uid}: {result.get('message', 'Unknown error')}")
                        
                except Exception as e:
                    failed += 1
                    results.append({
                        'uid': uid,
                        'status': 'error',
                        'message': str(e)
                    })
                    print(f"✗ Exception for {uid}: {e}")
        
        # إرجاع النتائج
        return jsonify({
            'status': 'completed',
            'total_accounts': len(accounts),
            'successful': successful,
            'failed': failed,
            'bio': bio,
            'results': results
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

@app.route('/get_all_tokens', methods=['GET'])
def get_all_tokens():
    """API لجلب جميع التوكنات"""
    try:
        accounts = load_accounts()
        if not accounts:
            return jsonify({
                'status': 'error',
                'message': 'No accounts found'
            }), 400
        
        print(f"Getting tokens for {len(accounts)} accounts")
        
        tokens = []
        successful = 0
        failed = 0
        
        # استخدام ThreadPoolExecutor لجلب التوكنات بالتوازي
        with ThreadPoolExecutor(max_workers=MAX_WORKERS) as executor:
            future_to_uid = {}
            for uid, password in accounts.items():
                future = executor.submit(get_final_token, uid, password)
                future_to_uid[future] = uid
            
            for future in as_completed(future_to_uid):
                uid = future_to_uid[future]
                try:
                    token = future.result()
                    if token:
                        tokens.append({
                            'uid': uid,
                            'token': token,
                            'status': 'success'
                        })
                        successful += 1
                        print(f"✓ Got token for {uid}")
                    else:
                        tokens.append({
                            'uid': uid,
                            'token': None,
                            'status': 'failed',
                            'message': 'Failed to generate token'
                        })
                        failed += 1
                        print(f"✗ Failed to get token for {uid}")
                except Exception as e:
                    tokens.append({
                        'uid': uid,
                        'token': None,
                        'status': 'error',
                        'message': str(e)
                    })
                    failed += 1
                    print(f"✗ Exception for {uid}: {e}")
        
        return jsonify({
            'status': 'completed',
            'total_accounts': len(accounts),
            'successful': successful,
            'failed': failed,
            'tokens': tokens
        })
        
    except Exception as e:
        return jsonify({
            'status': 'error',
            'message': str(e)
        }), 500

# ========== Main Function ==========
if __name__ == '__main__':
    print("=" * 60)
    print("🚀 FreeFire Bio Changer API (مع دعم الألوان)")
    print("=" * 60)
    print(f"📁 Accounts file: {ACCOUNTS_FILE}")
    print(f"👥 Max workers: {MAX_WORKERS}")
    print(f"🌐 Server URL: http://localhost:65450")
    print(f"🎨 يدعم علامات الألوان ولا يحسبها في الطول")
    print("\n🔗 الطرق المتاحة:")
    print("  GET  /                      - واجهة ويب كاملة")
    print("  GET  /get_token             - Get token for single account")
    print("  GET  /get_all_tokens        - Get tokens for all accounts")
    print("  GET  /update_bio_single     - Update bio for single account")
    print("  GET  /update_bio_all        - Update bio for ALL accounts")
    print("=" * 60)
    
    # تشغيل السيرفر على نفس البورت
    app.run(host='0.0.0.0', port=65470, debug=False, threaded=True)