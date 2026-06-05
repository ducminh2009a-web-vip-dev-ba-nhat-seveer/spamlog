from flask import Flask, request, jsonify
from flask_cors import CORS
import requests
from Crypto.Cipher import AES
from Crypto.Util.Padding import pad, unpad
from datetime import datetime
import base64, json, time, socket, os, logging
import urllib3
from functools import wraps
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

# Store login results
login_cache = {}

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
    p = token.split('.')[1]
    p += '=' * (-len(p) % 4)
    return json.loads(base64.urlsafe_b64decode(p))

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

# ── MajorLogin
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

    try:
        import MajorLogin_res_pb2
        res = MajorLogin_res_pb2.MajorLoginRes()
        try:
            dec = aes_decrypt(resp.content, AES_KEY, AES_IV)
            res.ParseFromString(dec)
        except:
            res.ParseFromString(resp.content)
        return res.account_jwt, res.key.hex(), res.iv.hex(), 0
    except Exception as e:
        raise Exception(f"Parse MajorLogin response error: {e}")

# ── GetLoginData
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

    parsed = _parse_proto_raw(resp.content)

    def _str(v):
        if isinstance(v, bytes): 
            return v.decode()
        return str(v)

    online_addr = _str(parsed.get(14, ''))
    whisper_addr = _str(parsed.get(32, '')) if 32 in parsed else None

    if not online_addr:
        raise Exception("Game server address not found")

    online_ip = online_addr[:-6]
    online_port = int(online_addr[-5:])
    whisper_ip = whisper_port = None
    
    if whisper_addr:
        whisper_ip = whisper_addr[:-6]
        whisper_port = int(whisper_addr[-5:])

    return whisper_ip, whisper_port, online_ip, online_port

def _parse_proto_raw(data: bytes) -> dict:
    result = {}
    idx = 0
    while idx < len(data):
        tag = data[idx]
        idx += 1
        fn = tag >> 3
        wt = tag & 0x07
        if wt == 0:
            val = 0
            shift = 0
            while idx < len(data):
                b = data[idx]
                idx += 1
                val |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            result[fn] = val
        elif wt == 2:
            ln = 0
            shift = 0
            while idx < len(data):
                b = data[idx]
                idx += 1
                ln |= (b & 0x7F) << shift
                if not (b & 0x80):
                    break
                shift += 7
            vb = data[idx:idx+ln]
            idx += ln
            try:
                result[fn] = vb.decode('utf-8')
            except:
                result[fn] = vb
        else:
            break
    return result

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

# ── Send packet to server
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

# ── API Endpoint chính

@app.route('/spamlog', methods=['GET', 'POST'])
def spamlog():
    """
    Endpoint: /spamlog?access={accesstoken}
    Method: GET hoặc POST
    """
    # Lấy access token từ query parameter
    access_token = request.args.get('access')
    
    # Nếu không có trong query, thử lấy từ JSON body (cho POST request)
    if not access_token and request.is_json:
        data = request.get_json()
        access_token = data.get('access') or data.get('access_token')
    
    if not access_token:
        return jsonify({
            'success': False,
            'error': 'Missing access token. Use: /spamlog?access=YOUR_TOKEN'
        }), 400
    
    logger.info(f"Processing spamlog request for token: {access_token[:20]}...")
    
    try:
        # Step 1: Validate token
        open_id, platform = inspect_token(access_token)
        logger.info(f"Token valid: open_id={open_id}, platform={platform}")
        
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
        
        # Step 5: Send packet to whisper server (if available)
        whisper_result = None
        if whisper_ip and whisper_port:
            success, result = send_packet(whisper_ip, whisper_port, packet)
            whisper_result = {
                'sent': success,
                'server': f"{whisper_ip}:{whisper_port}",
                'result': result if not success else 'Packet sent'
            }
            logger.info(f"Whisper: {whisper_result}")
        
        # Step 6: Send packet to game server
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
        
        # Thêm whisper info nếu có
        if whisper_result:
            response_data['whisper_server'] = whisper_result
        
        # Cache kết quả
        cache_key = access_token[:50]
        login_cache[cache_key] = {
            **response_data,
            'full_packet_hex': packet_hex,  # Lưu full packet trong cache
            'cached_at': datetime.now().isoformat()
        }
        
        logger.info(f"Spamlog completed: success={game_success}")
        return jsonify(response_data)
        
    except Exception as e:
        logger.error(f"Spamlog error: {str(e)}")
        return jsonify({
            'success': False,
            'access_token': access_token[:30] + '...' if len(access_token) > 30 else access_token,
            'error': str(e),
            'timestamp': datetime.now().isoformat()
        }), 500

# ── Additional endpoints

@app.route('/', methods=['GET'])
def home():
    return jsonify({
        'name': 'Free Fire SpamLog API',
        'version': '2.0.0',
        'endpoints': {
            '/spamlog': 'GET/POST - Main endpoint. Usage: /spamlog?access=YOUR_TOKEN',
            '/spamlog/bulk': 'POST - Bulk spamlog with multiple tokens',
            '/cache': 'GET - View cached results',
            '/health': 'GET - Health check'
        }
    })

@app.route('/spamlog/bulk', methods=['POST'])
def spamlog_bulk():
    """
    Bulk spamlog với nhiều token
    Request body: {"tokens": ["token1", "token2", ...]}
    """
    data = request.get_json()
    if not data or 'tokens' not in data:
        return jsonify({'error': 'Missing tokens array'}), 400
    
    tokens = data['tokens']
    results = []
    
    for token in tokens:
        try:
            open_id, platform = inspect_token(token)
            jwt_token, key, iv, ts = major_login(open_id, token, platform)
            whisper_ip, whisper_port, online_ip, online_port = get_login_data(
                jwt_token, open_id, token, platform
            )
            packet = build_login_packet(jwt_token, key, iv, ts)
            
            # Send packet
            success, response = send_packet(online_ip, online_port, packet)
            
            results.append({
                'token': token[:30] + '...',
                'success': success,
                'server': f"{online_ip}:{online_port}",
                'response': response if response else 'No response'
            })
            
            time.sleep(0.5)  # Delay to avoid rate limit
            
        except Exception as e:
            results.append({
                'token': token[:30] + '...',
                'success': False,
                'error': str(e)
            })
    
    return jsonify({
        'total': len(tokens),
        'successful': sum(1 for r in results if r.get('success')),
        'results': results
    })

@app.route('/cache', methods=['GET'])
def get_cache():
    """View cached results"""
    return jsonify({
        'cached_tokens': len(login_cache),
        'entries': login_cache
    })

@app.route('/cache/<path:token>', methods=['GET'])
def get_cached_token(token):
    """Get cached result for specific token"""
    cache_key = token[:50]
    if cache_key in login_cache:
        return jsonify(login_cache[cache_key])
    return jsonify({'error': 'Token not found in cache'}), 404

@app.route('/health', methods=['GET'])
def health():
    return jsonify({
        'status': 'healthy',
        'timestamp': datetime.now().isoformat(),
        'cache_size': len(login_cache)
    })

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    host = os.environ.get('HOST', '0.0.0.0')
    
    print(f"""
    ╔══════════════════════════════════════════════════════════╗
    ║          Free Fire SpamLog API - Running                  ║
    ║                                                           ║
    ║     Usage: GET /spamlog?access=YOUR_TOKEN                 ║
    ║                                                           ║
    ║     Example:                                              ║
    ║     curl "http://{host}:{port}/spamlog?access=abc123"      ║
    ║                                                           ║
    ║     Server: http://{host}:{port}                          ║
    ╚══════════════════════════════════════════════════════════╝
    """)
    
    app.run(host=host, port=port, debug=False, threaded=True)