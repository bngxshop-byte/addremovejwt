from flask import Flask, request, jsonify
from datetime import datetime
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
import binascii
import urllib3
from concurrent.futures import ThreadPoolExecutor

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)

# نسمح بـ 50 طلب متزامن
executor = ThreadPoolExecutor(max_workers=50)

# المتغيرات الثابتة للتشفير
DEC = ['80', '81', '82', '83', '84', '85', '86', '87', '88', '89', '8a', '8b', '8c', '8d', '8e', '8f', '90', '91', '92', '93', '94', '95', '96', '97', '98', '99', '9a', '9b', '9c', '9d', '9e', '9f', 'a0', 'a1', 'a2', 'a3', 'a4', 'a5', 'a6', 'a7', 'a8', 'a9', 'aa', 'ab', 'ac', 'ad', 'ae', 'af', 'b0', 'b1', 'b2', 'b3', 'b4', 'b5', 'b6', 'b7', 'b8', 'b9', 'ba', 'bb', 'bc', 'bd', 'be', 'bf', 'c0', 'c1', 'c2', 'c3', 'c4', 'c5', 'c6', 'c7', 'c8', 'c9', 'ca', 'cb', 'cc', 'cd', 'ce', 'cf', 'd0', 'd1', 'd2', 'd3', 'd4', 'd5', 'd6', 'd7', 'd8', 'd9', 'da', 'db', 'dc', 'dd', 'de', 'df', 'e0', 'e1', 'e2', 'e3', 'e4', 'e5', 'e6', 'e7', 'e8', 'e9', 'ea', 'eb', 'ec', 'ed', 'ee', 'ef', 'f0', 'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'fa', 'fb', 'fc', 'fd', 'fe', 'ff']

XXX = ['1', '01', '02', '03', '04', '05', '06', '07', '08', '09', '0a', '0b', '0c', '0d', '0e', '0f', '10', '11', '12', '13', '14', '15', '16', '17', '18', '19', '1a', '1b', '1c', '1d', '1e', '1f', '20', '21', '22', '23', '24', '25', '26', '27', '28', '29', '2a', '2b', '2c', '2d', '2e', '2f', '30', '31', '32', '33', '34', '35', '36', '37', '38', '39', '3a', '3b', '3c', '3d', '3e', '3f', '40', '41', '42', '43', '44', '45', '46', '47', '48', '49', '4a', '4b', '4c', '4d', '4e', '4f', '50', '51', '52', '53', '54', '55', '56', '57', '58', '59', '5a', '5b', '5c', '5d', '5e', '5f', '60', '61', '62', '63', '64', '65', '66', '67', '68', '69', '6a', '6b', '6c', '6d', '6e', '6f', '70', '71', 
       '72', '73', '74', '75', '76', '77', '78', '79', '7a', '7b', '7c', '7d', '7e', '7f']

# ==================== دوال التشفير الأساسية ====================
def encrypt_api(plain_text):
    """تشفير API"""
    plain_text = bytes.fromhex(plain_text)
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def decrypt_api(cipher_text):
    """فك تشفير API"""
    key = bytes([89, 103, 38, 116, 99, 37, 68, 69, 117, 104, 54, 37, 90, 99, 94, 56])
    iv = bytes([54, 111, 121, 90, 68, 114, 50, 50, 69, 51, 121, 99, 104, 106, 77, 37])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(bytes.fromhex(cipher_text)), AES.block_size)
    return plain_text.hex()

def encrypt_packet(plain_text):
    """تشفير باكيت AES"""
    plain_text = bytes.fromhex(plain_text)
    key = bytes([101, 116, 33, 120, 72, 83, 97, 119, 82, 94, 37, 56, 74, 50, 83, 53])
    iv = bytes([84, 76, 82, 118, 120, 100, 114, 114, 117, 51, 37, 80, 85, 113, 65, 54])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    cipher_text = cipher.encrypt(pad(plain_text, AES.block_size))
    return cipher_text.hex()

def decrypt_packet(packet):
    """فك تشفير باكيت"""
    packet = bytes.fromhex(packet)
    key = bytes([101, 116, 33, 120, 72, 83, 97, 119, 82, 94, 37, 56, 74, 50, 83, 53])
    iv = bytes([84, 76, 82, 118, 120, 100, 114, 114, 117, 51, 37, 80, 85, 113, 65, 54])
    cipher = AES.new(key, AES.MODE_CBC, iv)
    plain_text = unpad(cipher.decrypt(packet), AES.block_size)
    return plain_text.hex()

def Decrypt_ID(da):
    """فك تشفير ID"""
    if da is not None and len(da) == 10:
        w = 128
        xxx = len(da) / 2 - 1
        xxx = str(xxx)[:1]
        for _ in range(int(xxx) - 1):
            w = w * 128
        x1 = da[:2]
        x2 = da[2:4]
        x3 = da[4:6]
        x4 = da[6:8]
        x5 = da[8:10]
        return str(w * XXX.index(x5) + (DEC.index(x2) * 128) + DEC.index(x1) + 
                  (DEC.index(x3) * 128 * 128) + (DEC.index(x4) * 128 * 128 * 128))

    if da is not None and len(da) == 8:
        w = 128
        xxx = len(da) / 2 - 1
        xxx = str(xxx)[:1]
        for _ in range(int(xxx) - 1):
            w = w * 128
        x1 = da[:2]
        x2 = da[2:4]
        x3 = da[4:6]
        x4 = da[6:8]
        return str(w * XXX.index(x4) + (DEC.index(x2) * 128) + DEC.index(x1) + 
                  (DEC.index(x3) * 128 * 128))
    
    return None

def Encrypt_ID(x):
    """تشفير ID"""
    x = int(x)
    x = x / 128
    
    if x > 128:
        x = x / 128
        if x > 128:
            x = x / 128
            if x > 128:
                x = x / 128
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                m = (n - int(strn)) * 128
                return DEC[int(m)] + DEC[int(n)] + DEC[int(z)] + DEC[int(y)] + XXX[int(x)]
            else:
                strx = int(x)
                y = (x - int(strx)) * 128
                stry = str(int(y))
                z = (y - int(stry)) * 128
                strz = str(int(z))
                n = (z - int(strz)) * 128
                strn = str(int(n))
                return DEC[int(n)] + DEC[int(z)] + DEC[int(y)] + XXX[int(x)]
        else:
            strx = int(x)
            y = (x - int(strx)) * 128
            stry = str(int(y))
            z = (y - int(stry)) * 128
            strz = str(int(z))
            return DEC[int(z)] + DEC[int(y)] + XXX[int(x)]
    else:
        strx = int(x)
        if strx == 0:
            y = (x - int(strx)) * 128
            inty = int(y)
            return XXX[inty]
        else:
            y = (x - int(strx)) * 128
            stry = str(int(y))
            return DEC[int(y)] + XXX[int(x)]

# ==================== دوال جلب التوكن ====================
def TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid):
    """إنشاء التوكن الجديد"""
    now = datetime.now()
    now = str(now)[:len(str(now)) - 7]
    data = bytes.fromhex('1a13323032352d30332d30362030363a32343a3135220966726565206669726528013a07312e3132332e314232416e64726f6964204f532039202f204150492d3238202850492f72656c2e636a772e32303232303531382e313134313333294a0848616e6468656c64520d41542654204d6f62696c6974795a045749464960800a68d00572033234307a2d7838362d3634205353453320535345342e3120535345342e32204156582041565832207c2032343030207c20348001e61e8a010f416472656e6f2028544d292036343092010d4f70656e474c20455320332e309a012b476f6f676c657c31623833656335362d363635662d343064392d613436372d303637396438623762306231a2010d37342e3230382e3139372e3230aa0102656eb201206332303962666537343263306532613363613339656631313366336663613430ba010134c2010848616e6468656c64ca01104173757320415355535f493030354441ea014063643030633331363466373361393935373964306238363032643932653137636437353863383262306265353239303839376564346638663161353665333937f00101ca020d41542654204d6f62696c697479d2020457494649ca03203161633462383065636630343738613434323033626638666163363132306635e003a28c02e803bdef01f003af13f80392078004e9fa018804a28c029004e9fa019804a28c02b00404c80401d2043d2f646174612f6170702f636f6d2e6474732e667265656669726574682d4a775553566677524542514277456c7045704d3455673d3d2f6c69622f61726de00401ea045f35623839326161616264363838653537316636383830353331313861313632627c2f646174612f6170702f636f6d2e6474732e667265656669726574682d4a775553566677524542514277456c7045704d3455673d3d2f626173652e61706bf00406f804018a050233329a050a32303139313138313035a80503b205094f70656e474c455332b805ff01c00504ca0522450147130554590145045d1009044c5945395b0455040d6c5c515760020e6f010f30e005e6b201ea05093372645f7061727479f2055c4b717348547a4232754c4c5351667a71317453626639565049307555466b683673596b556d7735516a78526230396a35663644366e6177466f367249666a302b57736f725a32655a5737556138444b556f546375626862435651513df805e7e4068806019006019a060134a2060134')
    data = data.replace(OLD_OPEN_ID.encode(), NEW_OPEN_ID.encode())
    data = data.replace(OLD_ACCESS_TOKEN.encode(), NEW_ACCESS_TOKEN.encode())
    d = encrypt_api(data.hex())
    Final_Payload = bytes.fromhex(d)
    
    headers = {
        "Host": "loginbp.ggblueshark.com",
        "X-Unity-Version": "2018.4.11f1",
        "Accept": "*/*",
        "Authorization": "Bearer",
        "ReleaseVersion": "OB53",
        "X-GA": "v1 1",
        "Accept-Encoding": "gzip, deflate, br",
        "Accept-Language": "en-GB,en-US;q=0.9,en;q=0.8",
        "Content-Type": "application/x-www-form-urlencoded",
        "Content-Length": str(len(Final_Payload)),
        "User-Agent": "Free%20Fire/2019118692 CFNetwork/3826.500.111.2.2 Darwin/24.4.0",
        "Connection": "keep-alive"
    }
    
    URL = "https://loginbp.ggblueshark.com/MajorLogin"
    RESPONSE = requests.post(URL, headers=headers, data=Final_Payload, verify=False)
    
    if RESPONSE.status_code == 200:
        if len(RESPONSE.text) < 10:
            return False
        BASE64_TOKEN = RESPONSE.text[RESPONSE.text.find("eyJhbGciOiJIUzI1NiIsInN2ciI6IjEiLCJ0eXAiOiJKV1QifQ"):-1]
        second_dot_index = BASE64_TOKEN.find(".", BASE64_TOKEN.find(".") + 1)
        BASE64_TOKEN = BASE64_TOKEN[:second_dot_index + 44]
        return BASE64_TOKEN
    else:
        print(f"MajorLogin failed with status: {RESPONSE.status_code}")
        print(f"Response: {RESPONSE.text}")
        return False

# ==================== دوال المساعدة للطلبات ====================
def send_request(token, uid, endpoint):
    """إرسال طلب إلى السيرفر"""
    uid = int(uid)
    id_encrypted = Encrypt_ID(uid)
    data0 = "08c8b5cfea1810" + id_encrypted + "18012008"
    data = bytes.fromhex(encrypt_api(data0))
    
    url = f"https://clientbp.common.ggbluefox.com/{endpoint}"
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Connection': 'Keep-Alive',
        'Expect': '100-continue',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB52',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    try:
        response = requests.post(url, headers=headers, data=data, verify=False, timeout=15)
        
        if response.status_code == 200:
            return {"status": "success", "message": "Operation completed!"}
        else:
            return {"status": "failed", "code": response.status_code, "response": response.text[:500]}
    except Exception as e:
        return {"status": "error", "message": str(e)}

def send_request_detailed(token, uid, endpoint):
    """إرسال طلب مع تفاصيل الرد"""
    uid = int(uid)
    id_encrypted = Encrypt_ID(uid)
    data0 = "08c8b5cfea1810" + id_encrypted + "18012008"
    data = bytes.fromhex(encrypt_api(data0))
    
    url = f"https://clientbp.common.ggbluefox.com/{endpoint}"
    headers = {
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; ASUS_Z01QD Build/PI)',
        'Authorization': f'Bearer {token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': 'OB52',
        'Content-Type': 'application/x-www-form-urlencoded',
    }

    try:
        response = requests.post(url, headers=headers, data=data, verify=False, timeout=15)
        
        # معلومات الرد
        result = {
            "http_status": response.status_code,
            "headers": dict(response.headers),
            "raw_length": len(response.content),
            "raw_hex": binascii.hexlify(response.content).decode()[:500] if response.content else ""
        }

        # محاولة فك JSON
        try:
            result["json"] = response.json()
        except:
            result["text"] = response.text[:500]

        return result
    except Exception as e:
        return {"error": str(e)}

# ==================== نقاط API ====================
@app.route('/get_token', methods=['GET'])
def get_token():
    """جلب التوكن من UID و Password"""
    try:
        uid = request.args.get('uid')
        password = request.args.get('password')
        
        if not uid or not password:
            return jsonify({"status": "error", "message": "Missing uid or password"}), 400
            
        url = "https://100067.connect.garena.com/oauth/guest/token/grant"
        headers = {
            "Host": "100067.connect.garena.com",
            "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)",
            "Content-Type": "application/x-www-form-urlencoded",
            "Accept-Encoding": "gzip, deflate, br",
            "Connection": "close",
        }
        data = {
            "uid": f"{uid}",
            "password": f"{password}",
            "response_type": "token",
            "client_type": "2",
            "client_secret": "",
            "client_id": "100067",
        }
        response = requests.post(url, headers=headers, data=data)
        
        try:
            data = response.json()
        except Exception as e:
            return jsonify({"status": "error", "message": "Invalid response from Garena"})

        if "access_token" not in data or "open_id" not in data:
            return jsonify({"status": "error", "message": f"Missing keys in response: {data}"})

        NEW_ACCESS_TOKEN = data['access_token']
        NEW_OPEN_ID = data['open_id']
        OLD_ACCESS_TOKEN = "cd00c3164f73a99579d0b8602d92e17cd758c82b0be5290897ed4f8f1a56e397"
        OLD_OPEN_ID = "c209bfe742c0e2a3ca39ef113f3fca40"
        
        token = TOKEN_MAKER(OLD_ACCESS_TOKEN, NEW_ACCESS_TOKEN, OLD_OPEN_ID, NEW_OPEN_ID, uid)
        if token:
            return jsonify({"status": "success", "token": token})
        else:
            return jsonify({"status": "failure", "message": "Failed to generate token"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)})

@app.route("/add_friend", methods=["GET"])
def add_friend():
    """إضافة صديق"""
    token = request.args.get("token")
    uid = request.args.get("uid")

    if not token or not uid:
        return jsonify({"error": "Missing token or uid"}), 400

    # تنفيذ الطلب في خيط مستقل
    future = executor.submit(send_request, token, uid, "RequestAddingFriend")
    result = future.result()

    return jsonify(result)

@app.route("/remove_friend", methods=["GET"])
def remove_friend():
    """إزالة صديق"""
    token = request.args.get("token")
    uid = request.args.get("uid")

    if not token or not uid:
        return jsonify({"error": "Missing token or uid"}), 400

    # طلب مفصل مع معلومات الرد
    result = send_request_detailed(token, uid, "RemoveFriend")
    
    return jsonify(result), result.get("http_status", 500)

@app.route("/encrypt_id", methods=["GET"])
def encrypt_id_endpoint():
    """تشفير ID من خلال API"""
    uid = request.args.get("uid")
    if not uid:
        return jsonify({"error": "Missing uid"}), 400
    
    try:
        encrypted = Encrypt_ID(uid)
        return jsonify({"uid": uid, "encrypted": encrypted})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/decrypt_id", methods=["GET"])
def decrypt_id_endpoint():
    """فك تشفير ID من خلال API"""
    encrypted = request.args.get("encrypted")
    if not encrypted:
        return jsonify({"error": "Missing encrypted ID"}), 400
    
    try:
        decrypted = Decrypt_ID(encrypted)
        return jsonify({"encrypted": encrypted, "uid": decrypted})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/encrypt_api", methods=["GET"])
def encrypt_api_endpoint():
    """تشفير نص عبر AES"""
    text = request.args.get("text")
    if not text:
        return jsonify({"error": "Missing text"}), 400
    
    try:
        encrypted = encrypt_api(text)
        return jsonify({"original": text, "encrypted": encrypted})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/decrypt_api", methods=["GET"])
def decrypt_api_endpoint():
    """فك تشفير نص عبر AES"""
    text = request.args.get("text")
    if not text:
        return jsonify({"error": "Missing text"}), 400
    
    try:
        decrypted = decrypt_api(text)
        return jsonify({"encrypted": text, "decrypted": decrypted})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/health", methods=["GET"])
def health_check():
    """فحص حالة السيرفر"""
    return jsonify({
        "status": "healthy",
        "service": "Free Fire API Service",
        "endpoints": [
            "/get_token",
            "/add_friend", 
            "/remove_friend",
            "/encrypt_id",
            "/decrypt_id",
            "/encrypt_api",
            "/decrypt_api",
            "/health"
        ]
    })

@app.route("/", methods=["GET"])
def index():
    """الصفحة الرئيسية"""
    return jsonify({
        "message": "Free Fire API Service",
        "description": "خدمة API لإدارة أصدقاء Free Fire",
        "version": "1.0.0",
        "endpoints": {
            "get_token": "/get_token?uid=USER_ID&password=PASSWORD",
            "add_friend": "/add_friend?token=TOKEN&uid=FRIEND_UID",
            "remove_friend": "/remove_friend?token=TOKEN&uid=FRIEND_UID",
            "encrypt_id": "/encrypt_id?uid=USER_ID",
            "decrypt_id": "/decrypt_id?encrypted=ENCRYPTED_ID",
            "health": "/health"
        }
    })

if __name__ == '__main__':
    # تشغيل السيرفر على المنفذ 8792 (مثل الكود الأصلي)
    app.run(host='0.0.0.0', port=65470, debug=False)
