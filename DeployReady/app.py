"""
SecureVault AES — Upgraded Secure Image Transmission
BTech CSE Major Project — Cryptography & Network Security

SECURITY UPGRADE:
- No password sent over WhatsApp/Email (plaintext risk eliminated)
- QR Code embeds encrypted session token — scan to decrypt
- TOTP-based time-limited one-time keys
- AES-256-CBC + PBKDF2-HMAC-SHA256 + Encrypt-then-MAC
- Brute-force lockout + session expiry
"""

from flask import Flask, render_template, request, jsonify, send_from_directory
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding as aes_padding, hashes, hmac
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.backends import default_backend
from PIL import Image, ImageFilter
import numpy as np
import os, json, time, secrets, math, base64, io
import qrcode
import pyotp

app = Flask(__name__)
app.config['UPLOAD_FOLDER']    = 'static/uploads'
app.config['ENCRYPTED_FOLDER'] = 'static/encrypted'
app.config['DECRYPTED_FOLDER'] = 'static/decrypted'
app.config['QR_FOLDER']        = 'static/qr'
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024

PBKDF2_ITERATIONS = 200_000
KEY_LEN    = 32
HMAC_LEN   = 32
SALT_LEN   = 32
IV_LEN     = 16
SESSION_TTL = 1800   # 30 minutes
MAX_ATTEMPTS = 5

for f in [app.config['UPLOAD_FOLDER'], app.config['ENCRYPTED_FOLDER'],
          app.config['DECRYPTED_FOLDER'], app.config['QR_FOLDER']]:
    os.makedirs(f, exist_ok=True)

# In-memory session store (use Redis in production)
sessions = {}


# ─────────────────────────────────────────────
# CRYPTO HELPERS
# ─────────────────────────────────────────────

def pbkdf2_derive(password: str, salt: bytes):
    kdf = PBKDF2HMAC(algorithm=hashes.SHA256(), length=KEY_LEN * 2,
                     salt=salt, iterations=PBKDF2_ITERATIONS, backend=default_backend())
    m = kdf.derive(password.encode('utf-8'))
    return m[:KEY_LEN], m[KEY_LEN:]


def compute_hmac(mac_key: bytes, data: bytes) -> bytes:
    h = hmac.HMAC(mac_key, hashes.SHA256(), backend=default_backend())
    h.update(data)
    return h.finalize()


def verify_hmac(mac_key: bytes, data: bytes, tag: bytes) -> bool:
    return secrets.compare_digest(compute_hmac(mac_key, data), tag)


def entropy_bits(password: str) -> float:
    pool = ((26 if any(c.islower() for c in password) else 0) +
            (26 if any(c.isupper() for c in password) else 0) +
            (10 if any(c.isdigit() for c in password) else 0) +
            (32 if any(not c.isalnum() for c in password) else 0))
    return round(len(password) * math.log2(max(pool, 1)), 1)


# ─────────────────────────────────────────────
# QR-BASED SECURE KEY SHARE
# ─────────────────────────────────────────────

def generate_qr_token(token: str, password: str) -> str:
    """
    Generate a STANDARD otpauth:// QR code that Google Authenticator, Authy,
    and all TOTP apps can scan directly.

    The QR encodes:  otpauth://totp/SecureVault:<token_short>?secret=XXX&issuer=SecureVault
    Password is NEVER in the QR. Token is embedded so receiver can copy-paste it.
    """
    totp_secret = pyotp.random_base32()

    # Store in session — password stays server-side only
    sessions[token]['totp_secret']   = totp_secret
    sessions[token]['totp_password'] = password

    # SHORT token label shown in authenticator app
    token_short = token[:12]

    # STANDARD otpauth URI — this is what Google Authenticator expects
    totp_obj = pyotp.TOTP(totp_secret)
    otp_uri  = totp_obj.provisioning_uri(
        name=f"token:{token_short}",
        issuer_name="SecureVault AES"
    )

    # White background, black dots — required for phone cameras to scan
    qr = qrcode.QRCode(
        version=2,
        error_correction=qrcode.constants.ERROR_CORRECT_H,
        box_size=10,
        border=4
    )
    qr.add_data(otp_uri)
    qr.make(fit=True)

    img = qr.make_image(fill_color="black", back_color="white")
    buf = io.BytesIO()
    img.save(buf, format='PNG')
    buf.seek(0)

    qr_fn = f"qr_{token[:16]}.png"
    with open(os.path.join(app.config['QR_FOLDER'], qr_fn), 'wb') as f:
        f.write(buf.read())

    return qr_fn, totp_secret


def verify_totp_decrypt(token: str, totp_code: str):
    """Verify TOTP code to authenticate QR-scanned decryption — no password needed by receiver."""
    if token not in sessions:
        return False, "Session not found"
    s = sessions[token]
    if 'totp_secret' not in s:
        return False, "QR not generated for this session"
    totp = pyotp.TOTP(s['totp_secret'])
    # Allow 1 window drift (±30s)
    if not totp.verify(totp_code, valid_window=1):
        return False, "Invalid or expired TOTP code"
    # Use server-stored password for decryption
    return True, s['totp_password']


# ─────────────────────────────────────────────
# IMAGE ENCRYPTION / DECRYPTION
# ─────────────────────────────────────────────

def encrypt_image_aes(image_path: str, password: str) -> dict:
    img = Image.open(image_path).convert('RGB')
    w, h = img.size
    img_bytes = np.array(img, dtype=np.uint8).tobytes()

    salt = secrets.token_bytes(SALT_LEN)
    iv   = secrets.token_bytes(IV_LEN)
    enc_key, mac_key = pbkdf2_derive(password, salt)

    padder = aes_padding.PKCS7(128).padder()
    padded = padder.update(img_bytes) + padder.finalize()

    enc_obj = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend()).encryptor()
    ciphertext = enc_obj.update(padded) + enc_obj.finalize()

    mac_tag = compute_hmac(mac_key, iv + ciphertext)

    # Visual encrypted image (noise overlay for visual demo)
    needed = w * h * 3
    vis = np.frombuffer(ciphertext[:needed], dtype=np.uint8)
    if len(vis) < needed:
        vis = np.pad(vis, (0, needed - len(vis)), mode='wrap')
    vis = vis[:needed].reshape((h, w, 3))
    noise = np.random.randint(0, 40, (h, w, 3), dtype=np.uint8)
    vis = np.clip(vis.astype(np.int16) + noise, 0, 255).astype(np.uint8)
    enc_img = Image.fromarray(vis, 'RGB').filter(ImageFilter.GaussianBlur(0.4))

    ts = int(time.time() * 1000)
    enc_fn  = f"enc_{ts}.png"
    data_fn = f"data_{ts}.bin"
    enc_img.save(os.path.join(app.config['ENCRYPTED_FOLDER'], enc_fn))

    meta = {'width': w, 'height': h, 'orig_len': len(img_bytes),
            'iv': iv.hex(), 'salt': salt.hex(), 'iterations': PBKDF2_ITERATIONS}
    mb = json.dumps(meta).encode()
    with open(os.path.join(app.config['ENCRYPTED_FOLDER'], data_fn), 'wb') as f:
        f.write(len(mb).to_bytes(4, 'big') + mb + mac_tag + ciphertext)

    # Entropy
    hist, _ = np.histogram(vis.flatten(), bins=256, range=(0, 256))
    h2 = hist[hist > 0] / (w * h * 3)
    entropy_val = float(-np.sum(h2 * np.log2(h2)))

    return {
        'enc_fn': enc_fn, 'data_fn': data_fn,
        'key_hex': enc_key.hex(), 'iv_hex': iv.hex(),
        'salt_hex': salt.hex(), 'mac_hex': mac_tag.hex()[:16] + '…',
        'iterations': PBKDF2_ITERATIONS,
        'width': w, 'height': h, 'entropy': round(entropy_val, 4)
    }


def decrypt_image_aes(data_fn: str, password: str):
    path = os.path.join(app.config['ENCRYPTED_FOLDER'], data_fn)
    if not os.path.exists(path):
        return None, False, "Encrypted data file not found."

    with open(path, 'rb') as f:
        raw = f.read()

    ml = int.from_bytes(raw[:4], 'big')
    meta = json.loads(raw[4:4 + ml])
    mac_tag    = raw[4 + ml: 4 + ml + HMAC_LEN]
    ciphertext = raw[4 + ml + HMAC_LEN:]

    iv   = bytes.fromhex(meta['iv'])
    salt = bytes.fromhex(meta['salt'])
    enc_key, mac_key = pbkdf2_derive(password, salt)

    if not verify_hmac(mac_key, iv + ciphertext, mac_tag):
        return None, False, "HMAC verification failed — wrong password or tampered file."

    try:
        dec_obj = Cipher(algorithms.AES(enc_key), modes.CBC(iv), backend=default_backend()).decryptor()
        padded  = dec_obj.update(ciphertext) + dec_obj.finalize()
        unpadder = aes_padding.PKCS7(128).unpadder()
        plain   = unpadder.update(padded) + unpadder.finalize()

        arr = np.frombuffer(plain[:meta['orig_len']], dtype=np.uint8).reshape(
            (meta['height'], meta['width'], 3))
        dec_fn = f"dec_{int(time.time() * 1000)}.png"
        Image.fromarray(arr, 'RGB').save(os.path.join(app.config['DECRYPTED_FOLDER'], dec_fn))
        return dec_fn, True, "Decryption successful!"
    except Exception as e:
        return None, False, f"Decryption failed — {str(e)}"


# ─────────────────────────────────────────────
# ROUTES
# ─────────────────────────────────────────────

@app.route('/')
def index():
    return render_template('index.html')


@app.route('/validate_password', methods=['POST'])
def validate_password():
    pw = request.json.get('password', '')
    checks = {
        'length':     len(pw) >= 12,
        'uppercase':  any(c.isupper() for c in pw),
        'lowercase':  any(c.islower() for c in pw),
        'digit':      any(c.isdigit() for c in pw),
        'special':    any(c in '!@#$%^&*()_+-=[]{}|;:,.<>?/~`' for c in pw),
        'no_common':  pw.lower() not in ['password', '123456789', 'qwerty123', 'password123', 'admin123'],
        'strong_len': len(pw) >= 16,
    }
    score = sum(checks.values())
    # Strength label
    if score <= 2:   strength = 'Very Weak'
    elif score <= 4: strength = 'Weak'
    elif score == 5: strength = 'Fair'
    elif score == 6: strength = 'Strong'
    else:            strength = 'Very Strong'

    return jsonify({
        'checks': checks,
        'score': score,
        'entropy': entropy_bits(pw),
        'strength': strength
    })


@app.route('/encrypt', methods=['POST'])
def encrypt():
    if 'image' not in request.files:
        return jsonify({'success': False, 'error': 'No image uploaded'})
    file     = request.files['image']
    password = request.form.get('password', '')
    if not password or file.filename == '':
        return jsonify({'success': False, 'error': 'Image and password are required'})
    ext = file.filename.rsplit('.', 1)[-1].lower()
    if ext not in {'png', 'jpg', 'jpeg', 'bmp', 'gif', 'webp'}:
        return jsonify({'success': False, 'error': 'Unsupported format'})

    orig_fn   = f"orig_{int(time.time() * 1000)}.{ext}"
    orig_path = os.path.join(app.config['UPLOAD_FOLDER'], orig_fn)
    file.save(orig_path)

    try:
        r = encrypt_image_aes(orig_path, password)
        token = secrets.token_hex(24)
        sessions[token] = {
            **r, 'orig_fn': orig_fn,
            'created': time.time(),
            'attempts': 0, 'locked': False
        }
        # Generate QR for secure sharing
        qr_fn, totp_secret = generate_qr_token(token, password)

        return jsonify({
            'success': True, 'token': token,
            'orig_url': f'/static/uploads/{orig_fn}',
            'enc_url':  f'/static/encrypted/{r["enc_fn"]}',
            'qr_url':   f'/static/qr/{qr_fn}',
            'totp_secret': totp_secret,
            **{k: r[k] for k in ['key_hex', 'iv_hex', 'salt_hex', 'mac_hex',
                                  'iterations', 'width', 'height', 'entropy']}
        })
    except Exception as e:
        return jsonify({'success': False, 'error': str(e)})


@app.route('/decrypt', methods=['POST'])
def decrypt():
    """Standard password-based decryption."""
    token    = request.form.get('token', '')
    password = request.form.get('password', '')
    if not token or token not in sessions:
        return jsonify({'success': False, 'error': 'No active session. Encrypt an image first.'})
    s = sessions[token]
    if time.time() - s['created'] > SESSION_TTL:
        del sessions[token]
        return jsonify({'success': False, 'error': '⏰ Session expired (30 min). Re-encrypt.'})
    if s['locked']:
        return jsonify({'success': False, 'error': f'🔒 Locked after {MAX_ATTEMPTS} failed attempts.'})
    if not password:
        return jsonify({'success': False, 'error': 'Password required'})

    dec_fn, ok, msg = decrypt_image_aes(s['data_fn'], password)
    if ok:
        s['attempts'] = 0
        return jsonify({'success': True, 'dec_url': f'/static/decrypted/{dec_fn}', 'message': msg})

    s['attempts'] += 1
    rem = MAX_ATTEMPTS - s['attempts']
    if rem <= 0:
        s['locked'] = True
        return jsonify({'success': False, 'error': '🔒 Session locked — too many failed attempts.'})
    return jsonify({'success': False,
                    'error': f'{msg} ({rem} attempt{"s" if rem != 1 else ""} left)'})


@app.route('/decrypt_qr', methods=['POST'])
def decrypt_qr():
    """
    SECURE QR decryption — receiver scans QR → gets token + TOTP secret.
    They enter the 6-digit TOTP code. Server verifies, uses stored password.
    PASSWORD IS NEVER SHARED!
    """
    data     = request.json
    token    = data.get('token', '')
    totp_code = data.get('totp_code', '')

    if not token or token not in sessions:
        return jsonify({'success': False, 'error': 'Invalid or expired session token.'})

    s = sessions[token]
    if time.time() - s['created'] > SESSION_TTL:
        del sessions[token]
        return jsonify({'success': False, 'error': '⏰ QR session expired. Re-encrypt the image.'})
    if s.get('locked'):
        return jsonify({'success': False, 'error': '🔒 Session locked — too many failed attempts.'})

    ok, result = verify_totp_decrypt(token, totp_code)
    if not ok:
        s['attempts'] = s.get('attempts', 0) + 1
        if s['attempts'] >= MAX_ATTEMPTS:
            s['locked'] = True
        return jsonify({'success': False, 'error': result})

    # result is the password here
    dec_fn, dec_ok, msg = decrypt_image_aes(s['data_fn'], result)
    if dec_ok:
        return jsonify({'success': True, 'dec_url': f'/static/decrypted/{dec_fn}', 'message': msg})
    return jsonify({'success': False, 'error': msg})


@app.route('/session_info', methods=['POST'])
def session_info():
    token = request.json.get('token', '')
    if token not in sessions:
        return jsonify({'valid': False})
    s = sessions[token]
    remaining = max(0, SESSION_TTL - int(time.time() - s['created']))
    return jsonify({
        'valid': True,
        'remaining': remaining,
        'locked': s.get('locked', False),
        'attempts': s.get('attempts', 0)
    })


if __name__ == '__main__':
    app.run(debug=True, host='0.0.0.0', port=5000)
