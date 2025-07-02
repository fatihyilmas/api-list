# api/index.py

import os
import json
import base64
from flask import Flask, request, jsonify
import psycopg2  # Postgres için
from Crypto.Cipher import AES # Deşifreleme için

app = Flask(__name__)

# --- Yardımcı Fonksiyonlar ---

def get_db_connection():
    """Vercel tarafından sağlanan veritabanı URL'sinden bağlantı kurar."""
    try:
        conn = psycopg2.connect(os.environ.get("POSTGRES_URL"))
        return conn
    except Exception as e:
        print(f"Veritabanı bağlantı hatası: {e}")
        return None

def decrypt_data(encrypted_data_b64):
    """PHP'deki decrypt_from_python fonksiyonunun Python karşılığı."""
    try:
        key = hashlib.sha256(os.environ.get("API_SECRET_KEY").encode()).digest()
        data = base64.b64decode(encrypted_data_b64)
        iv = data[:16]
        ct = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = cipher.decrypt(ct)
        # PKCS7 padding'i temizle
        pad_len = decrypted[-1]
        return decrypted[:-pad_len].decode('utf-8')
    except Exception as e:
        print(f"Deşifreleme hatası: {e}")
        return None

# --- Ana İşleyici ---

@app.route('/api', methods=['POST'])
def handler():
    # 1. Gelen veriyi al ve deşifre et
    post_data = request.json
    if not post_data or 'encrypted_data' not in post_data:
        return jsonify({'success': False, 'message': 'Invalid or missing encrypted data.'}), 400

    decrypted_json = decrypt_data(post_data['encrypted_data'])
    if not decrypted_json:
        return jsonify({'success': False, 'message': 'Decryption failed.'}), 401

    payload = json.loads(decrypted_json)
    user_data = payload.get('user_data', {})
    email = user_data.get('email')

    if not email:
        return jsonify({'success': False, 'message': 'A valid email is required.'}), 400

    # 2. Veritabanına bağlan ve işlemleri yap
    conn = get_db_connection()
    if not conn:
        return jsonify({'success': False, 'message': 'Database connection error.'}), 500
    
    cur = conn.cursor()
    
    try:
        # Kullanıcıyı bul veya oluştur
        cur.execute("SELECT id FROM users WHERE email = %s;", (email,))
        user = cur.fetchone()
        
        if user:
            user_id = user[0]
            # Bakiye güncelleme
            if user_data.get('real_balance') is not None:
                cur.execute("UPDATE users SET bakiye = %s, last_activity = CURRENT_TIMESTAMP WHERE id = %s;", 
                            (user_data['real_balance'], user_id))
        else:
            cur.execute("INSERT INTO users (email, bakiye) VALUES (%s, %s) RETURNING id;", 
                        (email, user_data.get('real_balance')))
            user_id = cur.fetchone()[0]

        # Ayarları kaydet
        if user_data.get('settings'):
            cur.execute(
                "INSERT INTO user_settings_history (user_id, settings_data, version) VALUES (%s, %s, (SELECT COALESCE(MAX(version), 0) + 1 FROM user_settings_history WHERE user_id = %s));",
                (user_id, json.dumps(user_data['settings']), user_id)
            )

        # Logları kaydet
        if user_data.get('logs'):
            for log_type, logs in user_data['logs'].items():
                for log in logs:
                    cur.execute(
                        """INSERT INTO game_logs (user_id, game_mode, balance, bet_amount, total_bet_amount, status, bet_details, result_details) 
                           VALUES (%s, %s, %s, %s, %s, %s, %s, %s);""",
                        (
                            user_id, log_type, log.get('bakiye'), log.get('miktar'), log.get('toplam_miktar'),
                            log.get('durum', 'Beklemede'), log.get('oyun'), log.get('sayi') or log.get('renk') or log.get('rakam')
                        )
                    )
        
        conn.commit()
        return jsonify({'success': True, 'message': 'Sync successful.'})

    except Exception as e:
        conn.rollback()
        print(f"İşlem hatası: {e}")
        return jsonify({'success': False, 'message': 'An error occurred during transaction.'}), 500
    finally:
        cur.close()
        conn.close()

    return jsonify({"message": "OK"})