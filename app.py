from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import base64, json, time, socket, os, logging
import urllib3
import threading 

urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)

app = Flask(__name__)
CORS(app)

# Logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Constants
FREEFIRE_VERSION = "OB53"
AES_KEY = bytes([89,103,38,116,99,37,68,69,117,104,54,37,90,99,94,56])
AES_IV = bytes([54,111,121,90,68,114,50,50,69,51,121,99,104,106,77,37])

# Store login results and active spams
login_cache = {}
active_spams = {}  # {access_token: {'thread': thread, 'stop_event': event, 'start_time': datetime}}

# ── AES Functions
def aes_encrypt(data: bytes, key=AES_KEY, iv=AES_IV) -> bytes:
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return cipher.encrypt(pad(data, AES.block_size))

def aes_decrypt(data: bytes, key, iv) -> bytes:
    if isinstance(key, str): 
        key = bytes.fromhex(key)
    if isinstance(iv, str):  
        iv = bytes.fromhex(iv)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    return unpad(cipher.decrypt(data), AES.block_size)

def decode_jwt(token: str) -> dict:
    try:
        p = token.split('.')[1]
        p += '=' * (-len(p) % 4)
        return json.loads(base64.urlsafe_b64decode(p))
    except:
        return {}

# ── Protobuf functions
def _varint(v):
    r = bytearray()
    while v > 0x7F:
        r.append((v & 0x7F) | 0x80)
        v >>= 7
    r.append(v)
    return bytes(r)

def _str_field(field, value):
    if isinstance(value, str): 
        value = value.encode()
    return _varint((field << 3) | 2) + _varint(len(value)) + value

def build_login_payload(open_id: str, access_token: str, platform: int) -> bytes:
    now = str(datetime.now())[:19]
    pl = bytearray()
    pl += _str_field(3, now)
    pl += _str_field(22, open_id)
    pl += _str_field(23, str(platform))
    pl += _str_field(29, access_token)
    pl += _str_field(99, str(platform))
    return bytes(pl)

# ── Token inspection
def inspect_token(access_token: str):
    url = f"https://100067.connect.garena.com/oauth/token/inspect?token={access_token}"
    headers = {
        "Connection": "close",
        "Host": "100067.connect.garena.com",
        "User-Agent": "GarenaMSDK/4.0.19P4(G011A ;Android 9;en;US;)"
    }
    r = requests.get(url, headers=headers, timeout=10)
    d = r.json()
    if 'error' in d:
        raise Exception(f"Token error: {d.get('error')}")
    return d.get('open_id'), int(d.get('platform', 8))

# ── MajorLogin (DÙNG PROTOBUF)
def major_login(open_id: str, access_token: str, platform: int):
    url = "https://loginbp.ggpolarbear.com/MajorLogin"
    headers = {
        'X-Unity-Version': '2018.4.11f1',
        'ReleaseVersion': FREEFIRE_VERSION,
        'Content-Type': 'application/x-www-form-urlencoded',
        'X-GA': 'v1 1',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 7.1.2; ASUS_Z01QD Build/QKQ1.190825.002)',
        'Host': 'loginbp.ggpolarbear.com',
        'Connection': 'Keep-Alive'
    }

    raw_payload = build_login_payload(open_id, access_token, platform)
    enc_payload = aes_encrypt(raw_payload)

    resp = requests.post(url, headers=headers, data=enc_payload, verify=False, timeout=10)
    
    if resp.status_code != 200:
        raise Exception(f"MajorLogin failed HTTP {resp.status_code}")

    # Parse bằng protobuf
    try:
        import MajorLogin_res_pb2
        res = MajorLogin_res_pb2.MajorLoginRes()
        try:
            decrypted = aes_decrypt(resp.content, AES_KEY, AES_IV)
            res.ParseFromString(decrypted)
        except:
            res.ParseFromString(resp.content)
        
        jwt_token = res.account_jwt
        key = res.key.hex() if res.key else ""
        iv = res.iv.hex() if res.iv else ""
        
        if not jwt_token:
            raise Exception("Cannot extract jwt_token from response")
        
        return jwt_token, key, iv, 0
    except ImportError:
        # Fallback nếu không có protobuf
        return "", "", "", 0

# ── GetLoginData (DÙNG PROTOBUF)
def get_login_data(jwt_token: str, open_id: str, access_token: str, platform: int):
    raw_payload = build_login_payload(open_id, access_token, platform)
    enc_payload = aes_encrypt(raw_payload)

    url = "https://clientbp.ggpolarbear.com/GetLoginData"
    headers = {
        'Authorization': f'Bearer {jwt_token}',
        'X-Unity-Version': '2018.4.11f1',
        'X-GA': 'v1 1',
        'ReleaseVersion': FREEFIRE_VERSION,
        'Content-Type': 'application/x-www-form-urlencoded',
        'User-Agent': 'Dalvik/2.1.0 (Linux; U; Android 9; G011A Build/PI)',
        'Host': 'clientbp.ggpolarbear.com',
        'Connection': 'close'
    }
    resp = requests.post(url, headers=headers, data=enc_payload, verify=False, timeout=10)
    
    if resp.status_code != 200:
        raise Exception(f"GetLoginData failed HTTP {resp.status_code}")

    # Parse bằng protobuf
    try:
        import GetLoginData_res_pb2
        res = GetLoginData_res_pb2.GetLoginDataRes()
        res.ParseFromString(resp.content)
        
        online_addr = res.ip_port_online if res.ip_port_online else ""
        whisper_addr = res.ip_port_chat if res.ip_port_chat else ""

        if not online_addr:
            raise Exception("Game server address not found")

        online_ip = online_addr[:-6]
        online_port = int(online_addr[-5:])
        whisper_ip = whisper_port = None
        
        if whisper_addr and len(whisper_addr) > 6:
            whisper_ip = whisper_addr[:-6]
            whisper_port = int(whisper_addr[-5:])

        return whisper_ip, whisper_port, online_ip, online_port
    except ImportError:
        return None, None, None, None

# ── Build Login Packet
def build_login_packet(jwt_token: str, key, iv, ts) -> bytes:
    jwt_payload = decode_jwt(jwt_token)
    
    try:
        acc_id = int(jwt_payload.get('account_id', 0))
    except:
        acc_id = 0

    if isinstance(key, str):
        key = bytes.fromhex(key) if len(key) == 32 else key.encode()
    if isinstance(iv, str):
        iv = bytes.fromhex(iv) if len(iv) == 32 else iv.encode()

    enc_token = aes_encrypt(jwt_token.encode(), key, iv)
    body_len = len(enc_token)

    exp = int(jwt_payload.get('exp', 0))
    exp_adj = max(exp - 28800, 0)
    acc_hex = acc_id.to_bytes(8, "big").hex()
    time_hex = exp_adj.to_bytes(4, "big").hex()
    body_len_hex = body_len.to_bytes(4, "big").hex()
    header_hex = "0115" + acc_hex + time_hex + body_len_hex
    return bytes.fromhex(header_hex) + enc_token

# ── Send packet to server (1 lần)
def send_packet(ip, port, packet, timeout=5):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(timeout)
        s.connect((ip, int(port)))
        s.sendall(packet)
        
        try:
            response = s.recv(4096)
            response_hex = response.hex()
        except socket.timeout:
            response_hex = None
        
        s.close()
        return True, response_hex
    except Exception as e:
        return False, str(e)

# ── Spam worker (gửi liên tục)
def spam_worker(access_token: str, stop_event: threading.Event):
    """Gửi login packet liên tục cho đến khi dừng"""
    logger.info(f"[SPAM STARTED] Token: {access_token[:20]}...")
    
    try:
        # Lấy thông tin 1 lần
        open_id, platform = inspect_token(access_token)
        jwt_token, key, iv, ts = major_login(open_id, access_token, platform)
        whisper_ip, whisper_port, online_ip, online_port = get_login_data(
            jwt_token, open_id, access_token, platform
        )
        packet = build_login_packet(jwt_token, key, iv, ts)
        
        logger.info(f"[SPAM READY] Server: {online_ip}:{online_port}")
        
        count = 0
        while not stop_event.is_set():
            count += 1
            
            # Gửi đến whisper (nếu có)
            if whisper_ip and whisper_port:
                try:
                    ws = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    ws.settimeout(3)
                    ws.connect((whisper_ip, int(whisper_port)))
                    ws.send(packet)
                    ws.close()
                except:
                    pass
            
            # Gửi đến game server
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.settimeout(5)
                s.connect((online_ip, int(online_port)))
                s.sendall(packet)
                
                try:
                    data = s.recv(4096)
                    logger.info(f"[{count}] Sent OK | Recv {len(data)} bytes")
                except socket.timeout:
                    logger.info(f"[{count}] Sent OK | No response")
                s.close()
            except Exception as e:
                logger.error(f"[{count}] Error: {e}")
            
            # Đợi 1 giây (có thể dừng ngay lập tức)
            for _ in range(10):
                if stop_event.is_set():
                    break
                time.sleep(0.1)
        
        logger.info(f"[SPAM STOPPED] Token: {access_token[:20]}... | Sent: {count} packets")
        
    except Exception as e:
        logger.error(f"[SPAM ERROR] {access_token[:20]}...: {e}")

# ═══════════════════════════════════════════════════════════════
# API ENDPOINTS
# ═══════════════════════════════════════════════════════════════

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'name': 'Free Fire SpamLog API',
        'version': '4.0.0',
        'endpoints': {
            'GET /spamlog?access=TOKEN': 'Gửi login 1 lần',
            'GET /spamlog/start?access=TOKEN': 'Bắt đầu spam liên tục',
            'GET /stopspamlog?access=TOKEN': 'Dừng spam theo token',
            'GET /spamlog/status': 'Xem các spam đang chạy',
            'POST /stopall': 'Dừng tất cả spam',
            'GET /health': 'Health check'
        }
    })

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'active_spams': len(active_spams),
        'timestamp': datetime.now().isoformat()
    })

@app.route('/spamlog', methods=['GET', 'POST'])
def spamlog_once():
    """
    Gửi login packet 1 LẦN DUY NHẤT
    GET: /spamlog?access=TOKEN
    """
    access_token = request.args.get('access')
    
    if not access_token and request.is_json:
        data = request.get_json()
        access_token = data.get('access') or data.get('access_token')
    
    if not access_token:
        return jsonify({
            'success': False,
            'error': 'Missing access token. Use: /spamlog?access=YOUR_TOKEN'
        }), 400
    
    logger.info(f"Single send request for token: {access_token[:20]}...")
    
    try:
        # Step 1: Validate token
        open_id, platform = inspect_token(access_token)
        logger.info(f"Token valid: open_id={open_id}")
        
        # Step 2: MajorLogin
        jwt_token, key, iv, ts = major_login(open_id, access_token, platform)
        logger.info(f"MajorLogin successful")
        
        # Step 3: GetLoginData
        whisper_ip, whisper_port, online_ip, online_port = get_login_data(
            jwt_token, open_id, access_token, platform
        )
        logger.info(f"Game server: {online_ip}:{online_port}")
        
        # Step 4: Build packet
        packet = build_login_packet(jwt_token, key, iv, ts)
        packet_hex = packet.hex()
        logger.info(f"Packet built: {len(packet)} bytes")
        
        # Step 5: Send to whisper (if available)
        whisper_result = None
        if whisper_ip and whisper_port:
            success, result = send_packet(whisper_ip, whisper_port, packet, timeout=3)
            whisper_result = {
                'sent': success,
                'server': f"{whisper_ip}:{whisper_port}",
                'result': result if not success else 'Packet sent'
            }
        
        # Step 6: Send to game server
        game_success, game_result = send_packet(online_ip, online_port, packet)
        
        response_data = {
            'success': game_success,
            'access_token': access_token[:30] + '...' if len(access_token) > 30 else access_token,
            'open_id': open_id,
            'platform': platform,
            'game_server': {
                'ip': online_ip,
                'port': online_port,
                'address': f"{online_ip}:{online_port}"
            },
            'packet': {
                'size': len(packet),
                'hex': packet_hex[:100] + '...' if len(packet_hex) > 100 else packet_hex
            },
            'packet_sent': game_success,
            'server_response': game_result if game_result else 'No response (timeout)',
            'timestamp': datetime.now().isoformat()
        }
        
        if whisper_result:
            response_data['whisper_server'] = whisper_result
        
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Error: {str(e)}")
        return jsonify({
            'success': False,
            'access_token': access_token[:30] + '...' if len(access_token) > 30 else access_token,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

@app.route('/spamlog/start', methods=['GET', 'POST'])
def start_spam_continuous():
    """
    Bắt đầu spam LIÊN TỤC (gửi packet mỗi giây)
    GET: /spamlog/start?access=TOKEN
    """
    access_token = request.args.get('access')
    
    if not access_token and request.is_json:
        data = request.get_json()
        access_token = data.get('access_token') or data.get('access')
    
    if not access_token:
        return jsonify({
            'success': False,
            'error': 'Missing access token. Use: /spamlog/start?access=YOUR_TOKEN'
        }), 400
    
    # Kiểm tra đã spam chưa
    if access_token in active_spams:
        return jsonify({
            'success': False,
            'error': 'Token is already spamming. Use /stopspamlog?access=TOKEN to stop',
            'started_at': active_spams[access_token]['start_time'].isoformat()
        }), 409
    
    # Tạo stop event và thread
    stop_event = threading.Event()
    thread = threading.Thread(target=spam_worker, args=(access_token, stop_event))
    thread.daemon = True
    thread.start()
    
    # Lưu vào active_spams
    active_spams[access_token] = {
        'thread': thread,
        'stop_event': stop_event,
        'start_time': datetime.now()
    }
    
    return jsonify({
        'success': True,
        'message': 'Continuous spam started',
        'access_token': access_token[:30] + '...' if len(access_token) > 30 else access_token,
        'started_at': datetime.now().isoformat(),
        'note': 'Use /stopspamlog?access=TOKEN to stop'
    })

@app.route('/stopspamlog', methods=['GET', 'POST', 'DELETE'])
def stop_spam_continuous():
    """
    Dừng spam LIÊN TỤC theo access token
    GET: /stopspamlog?access=TOKEN
    """
    access_token = request.args.get('access')
    
    if not access_token and request.is_json:
        data = request.get_json()
        access_token = data.get('access_token') or data.get('access')
    
    if not access_token:
        return jsonify({
            'success': False,
            'error': 'Missing access token. Use: /stopspamlog?access=YOUR_TOKEN'
        }), 400
    
    # Kiểm tra có đang spam không
    if access_token not in active_spams:
        return jsonify({
            'success': False,
            'error': 'Token is not spamming',
            'active_tokens': list(active_spams.keys())
        }), 404
    
    # Dừng spam
    stop_event = active_spams[access_token]['stop_event']
    stop_event.set()
    
    # Đợi thread kết thúc
    thread = active_spams[access_token]['thread']
    thread.join(timeout=5)
    
    # Xóa khỏi danh sách
    del active_spams[access_token]
    
    return jsonify({
        'success': True,
        'message': 'Spam stopped',
        'access_token': access_token[:30] + '...' if len(access_token) > 30 else access_token,
        'stopped_at': datetime.now().isoformat()
    })

@app.route('/spamlog/status', methods=['GET'])
def get_spam_status():
    """Xem các spam đang chạy"""
    status = {}
    for token, data in active_spams.items():
        status[token[:30] + '...'] = {
            'started_at': data['start_time'].isoformat(),
            'running': data['thread'].is_alive()
        }
    
    return jsonify({
        'active_spams': len(active_spams),
        'tokens': status
    })

@app.route('/stopall', methods=['POST', 'DELETE'])
def stop_all_spams():
    """Dừng tất cả spam đang chạy"""
    count = len(active_spams)
    
    for token, data in active_spams.items():
        data['stop_event'].set()
        data['thread'].join(timeout=2)
    
    active_spams.clear()
    
    return jsonify({
        'success': True,
        'message': f'Stopped {count} spam threads',
        'stopped_at': datetime.now().isoformat()
    })

# ═══════════════════════════════════════════════════════════════
# MAIN
# ═══════════════════════════════════════════════════════════════

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    
    print("""
    ╔══════════════════════════════════════════════════════════════════╗
    ║                    FREE FIRE SPAMLOG API                         ║
    ║                         HOÀN CHỈNH                               ║
    ╠══════════════════════════════════════════════════════════════════╣
    ║                                                                  ║
    ║  📌 CÁCH DÙNG:                                                   ║
    ║                                                                  ║
    ║  • Gửi 1 lần:      GET /spamlog?access=TOKEN                     ║
    ║  • Spam liên tục:  GET /spamlog/start?access=TOKEN               ║
    ║  • Dừng spam:      GET /stopspamlog?access=TOKEN                 ║
    ║  • Xem trạng thái: GET /spamlog/status                           ║
    ║  • Dừng tất cả:    POST /stopall                                 ║
    ║                                                                  ║
    ╚══════════════════════════════════════════════════════════════════╝
    """)
    
    print(f"  🌐 Server running on: http://{host}:{port}\n")
    
    app.run(host=host, port=port, debug=False, threaded=True)