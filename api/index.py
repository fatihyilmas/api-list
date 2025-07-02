import os
import json
import base64
import hashlib
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
import psycopg2
from psycopg2 import Error as PgError
from psycopg2.extras import RealDictCursor
from vercel_python_helper import VercelRequest, VercelResponse

# --- Güvenlik ve Yapılandırma ---
# Ortam değişkenlerinden API gizli anahtarını al
# Bu anahtar Vercel projesinin ortam değişkenlerinde (Environment Variables) ayarlanmalıdır.
API_SECRET_KEY = os.environ.get('API_SECRET_KEY')
if not API_SECRET_KEY:
    raise ValueError("API_SECRET_KEY ortam değişkeni ayarlanmamış.")
# Ortam değişkenlerinden PostgreSQL bağlantı dizesini al
POSTGRES_URL = os.environ.get('POSTGRES_URL')

def get_db_connection():
    """Veritabanı bağlantısını sağlar."""
    if not POSTGRES_URL:
        raise ValueError("POSTGRES_URL ortam değişkeni ayarlanmamış.")
    return psycopg2.connect(POSTGRES_URL)

def decrypt_from_python(encrypted_data_b64: str) -> str | None:
    """Python'dan gelen şifreli veriyi çözer."""
    try:
        key = hashlib.sha256(API_SECRET_KEY.encode('utf-8')).digest()
        data = base64.b64decode(encrypted_data_b64)
        
        if len(data) < 16: # IV boyutu
            return None

        iv = data[:16]
        ciphertext = data[16:]

        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted_padded_data = cipher.decrypt(ciphertext)
        decrypted_data = unpad(decrypted_padded_data, AES.block_size)
        return decrypted_data.decode('utf-8')
    except Exception:
        return None

def sync_data_to_db(payload: dict):
    """Veriyi veritabanı ile senkronize eder."""
    conn = None
    try:
        conn = get_db_connection()
        cur = conn.cursor()

        user_data = payload.get('user_data', {})
        email = user_data.get('email')
        if not email:
            raise ValueError('A valid email is required.')

        # Kullanıcıyı bul veya oluştur (UPSERT)
        cur.execute("SELECT id FROM users WHERE email = %s", (email,))
        user_id = cur.fetchone()

        if user_id:
            user_id = user_id[0]
            if 'real_balance' in user_data:
                cur.execute(
                    "UPDATE users SET bakiye = %s, last_activity = NOW() WHERE id = %s",
                    (user_data['real_balance'], user_id)
                )
        else:
            cur.execute(
                "INSERT INTO users (email, bakiye) VALUES (%s, %s) RETURNING id",
                (email, user_data.get('real_balance'))
            )
            user_id = cur.fetchone()[0]

        # Ayarları kaydet
        if user_data.get('settings'):
            cur.execute(
                "INSERT INTO user_settings_history (user_id, settings_data, version) "
                "VALUES (%s, %s, (SELECT COALESCE(MAX(version), 0) + 1 FROM user_settings_history WHERE user_id = %s))",
                (user_id, json.dumps(user_data['settings']), user_id)
            )

        # Logları kaydet
        if user_data.get('logs'):
            for log_type, logs in user_data['logs'].items():
                for log in logs:
                    cur.execute(
                        "INSERT INTO game_logs (user_id, game_mode, balance, bet_amount, total_bet_amount, status, bet_details, result_details) "
                        "VALUES (%s, %s, %s, %s, %s, %s, %s, %s)",
                        (
                            user_id,
                            log_type,
                            log.get('bakiye'),
                            log.get('miktar'),
                            log.get('toplam_miktar'),
                            log.get('durum', 'Beklemede'),
                            log.get('oyun'),
                            log.get('sayi') or log.get('renk') or log.get('rakam')
                        )
                    )
        
        conn.commit()
        return {'success': True, 'message': 'Sync successful.'}

    except (ValueError, PgError) as e:
        if conn:
            conn.rollback()
        return {'success': False, 'message': f'Database error: {e}'}
    except Exception as e:
        if conn:
            conn.rollback()
        return {'success': False, 'message': f'An unexpected error occurred: {e}'}
    finally:
        if conn:
            cur.close()
            conn.close()

def handler(request: VercelRequest) -> VercelResponse:
    """Vercel sunucusuz fonksiyonunun ana giriş noktası."""
    if request.method != 'POST':
        return VercelResponse(json.dumps({'success': False, 'message': 'Invalid request method.'}), status=405, headers={'Content-Type': 'application/json'})

    try:
        body = json.loads(request.body)
        encrypted_data = body.get('encrypted_data')

        if not encrypted_data:
            return VercelResponse(json.dumps({'success': False, 'message': 'Invalid or missing encrypted data.'}), status=400, headers={'Content-Type': 'application/json'})

        decrypted_json = decrypt_from_python(encrypted_data)
        if decrypted_json is None:
            return VercelResponse(json.dumps({'success': False, 'message': 'Decryption failed.'}), status=401, headers={'Content-Type': 'application/json'})

        payload = json.loads(decrypted_json)
        
        result = sync_data_to_db(payload)
        status_code = 200 if result.get('success') else 400
        return VercelResponse(json.dumps(result), status=status_code, headers={'Content-Type': 'application/json'})

    except json.JSONDecodeError:
        return VercelResponse(json.dumps({'success': False, 'message': 'Invalid JSON payload.'}), status=400, headers={'Content-Type': 'application/json'})
    except Exception as e:
        return VercelResponse(json.dumps({'success': False, 'message': f'Server error: {e}'}), status=500, headers={'Content-Type': 'application/json'})
