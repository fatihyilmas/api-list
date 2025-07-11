import os
import json
import base64
import hashlib
from http.server import BaseHTTPRequestHandler
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import psycopg2
from psycopg2 import Error as PgError
import requests # Ülke tespiti için

# --- Güvenlik ve Yapılandırma ---
API_SECRET_KEY = os.environ.get('API_SECRET_KEY')
POSTGRES_URL = os.environ.get('POSTGRES_URL')

# --- Yardımcı Fonksiyonlar ---
def get_country_from_ip(ip_address: str) -> str | None:
    """Verilen IP adresinden ülke kodunu alır."""
    try:
        # Yerel veya özel IP adreslerini atla
        if ip_address.startswith(('192.168.', '10.', '127.0.0.1')) or ':' in ip_address: # IPv6'yı şimdilik atla
            return None
        response = requests.get(f"https://ipapi.co/{ip_address}/country/", timeout=2)
        if response.status_code == 200:
            return response.text.strip()
        return None
    except requests.exceptions.RequestException:
        return None

def get_db_connection():
    if not POSTGRES_URL:
        raise ValueError("POSTGRES_URL ortam değişkeni ayarlanmamış.")
    return psycopg2.connect(POSTGRES_URL)

def _derive_key_from_secret(secret: str) -> bytes:
    """Derives a 256-bit encryption key from a shared secret using PBKDF2."""
    if not secret:
        raise ValueError("Shared secret is not provided.")
    salt = b'jbot_salt_v1'
    iterations = 100_000
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=iterations,
        backend=default_backend()
    )
    return kdf.derive(secret.encode('utf-8'))

def decrypt_from_python(encrypted_text_b64: str) -> str | None:
    """Decrypts a base64 encoded string encrypted with AES-GCM."""
    if not encrypted_text_b64 or not API_SECRET_KEY:
        return None
    try:
        key = _derive_key_from_secret(API_SECRET_KEY)
        data = base64.b64decode(encrypted_text_b64.encode('utf-8'))
        iv = data[:12]
        tag = data[12:28]
        ciphertext = data[28:]
        
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag),
            backend=default_backend()
        ).decryptor()
        
        return (decryptor.update(ciphertext) + decryptor.finalize()).decode('utf-8')
    except (ValueError, TypeError):
        # Handles base64 decoding errors or other issues
        return None

def sync_data_to_db(payload: dict, ip_address: str):
    conn = None
    try:
        if not API_SECRET_KEY or not POSTGRES_URL:
            raise ValueError("Ortam değişkenleri eksik.")
        
        country_code = get_country_from_ip(ip_address)

        conn = get_db_connection()
        cur = conn.cursor()
        user_data = payload.get('user_data', {})
        email = user_data.get('email')
        if not email: raise ValueError('Email gerekli.')

        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        user_id_row = cur.fetchone()
        user_id = user_id_row[0] if user_id_row else None

        if user_id:
            if 'real_balance' in user_data and user_data['real_balance'] is not None:
                cur.execute("UPDATE users SET bakiye = %s, ip = %s, ulke = %s, last_activity = NOW() WHERE id = %s", (user_data['real_balance'], ip_address, country_code, user_id))
        else:
            cur.execute("INSERT INTO users (email, bakiye, ip, ulke) VALUES (%s, %s, %s, %s) RETURNING id", (email, user_data.get('real_balance'), ip_address, country_code))
            user_id = cur.fetchone()[0]

        if user_data.get('settings'):
            cur.execute("INSERT INTO user_settings_history (user_id, settings_data, version) VALUES (%s, %s, (SELECT COALESCE(MAX(version), 0) + 1 FROM user_settings_history WHERE user_id = %s))", (user_id, json.dumps(user_data['settings']), user_id))

        if user_data.get('logs'):
            for log_type, logs in user_data['logs'].items():
                for log in logs:
                    # 0 değerinin NULL olarak yorumlanmasını engelle
                    result_details = log.get('sayi')
                    if result_details is None:
                        result_details = log.get('renk')
                    if result_details is None:
                        result_details = log.get('rakam')
                    
                    cur.execute("INSERT INTO game_logs (user_id, game_mode, balance, bet_amount, total_bet_amount, status, bet_details, result_details) VALUES (%s, %s, %s, %s, %s, %s, %s, %s)", (user_id, log_type, log.get('bakiye'), log.get('miktar'), log.get('toplam_miktar'), log.get('durum', 'Beklemede'), log.get('oyun'), result_details))
        
        conn.commit()
        return {'success': True, 'message': 'Sync successful.'}
    except Exception as e:
        if conn: conn.rollback()
        return {'success': False, 'message': str(e)}
    finally:
        if conn: cur.close(); conn.close()

class handler(BaseHTTPRequestHandler):
    def do_POST(self):
        try:
            ip_address = self.headers.get('CF-Connecting-IP', self.headers.get('X-Forwarded-For', self.client_address[0]))
            content_length = int(self.headers['Content-Length'])
            body = self.rfile.read(content_length)
            data = json.loads(body)
            
            encrypted_data = data.get('encrypted_data')
            if not encrypted_data:
                self._send_response(400, {'success': False, 'message': 'Invalid or missing encrypted data.'})
                return

            decrypted_json = decrypt_from_python(encrypted_data)
            if decrypted_json is None:
                self._send_response(401, {'success': False, 'message': 'Decryption failed.'})
                return

            payload = json.loads(decrypted_json)
            
            # Extract client_ip from the payload sent by the proxy
            client_ip_from_proxy = payload.get('client_ip', ip_address)

            result = sync_data_to_db(payload, client_ip_from_proxy)
            status_code = 200 if result.get('success') else 400
            self._send_response(status_code, result)

        except json.JSONDecodeError:
            self._send_response(400, {'success': False, 'message': 'Invalid JSON payload.'})
        except Exception as e:
            self._send_response(500, {'success': False, 'message': f'Server error: {str(e)}'})

    def _send_response(self, status_code, data):
        self.send_response(status_code)
        self.send_header('Content-type', 'application/json')
        self.end_headers()
        self.wfile.write(json.dumps(data).encode('utf-8'))
