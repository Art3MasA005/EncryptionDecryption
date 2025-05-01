from flask import Flask, request, jsonify
from flask_cors import CORS
import base64
import json
import os

from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.PublicKey import RSA
from Crypto.Random import get_random_bytes
from Crypto.Util.Padding import pad, unpad

app = Flask(__name__)
CORS(app)

USERS_FILE = 'users.json'


# ---------- USER AUTHENTICATION ----------

def load_users():
    if os.path.exists(USERS_FILE):
        with open(USERS_FILE, 'r') as f:
            return json.load(f)
    return []

def save_users(users):
    with open(USERS_FILE, 'w') as f:
        json.dump(users, f, indent=4)

@app.route('/signup', methods=['POST'])
def signup():
    data = request.json
    username = data['username']
    password = data['password']

    users = load_users()
    if any(user['username'] == username for user in users):
        return jsonify({'error': 'Username already exists'}), 400

    users.append({'username': username, 'password': password})
    save_users(users)
    return jsonify({'message': 'Signup successful'}), 200

@app.route('/login', methods=['POST'])
def login():
    data = request.json
    username = data['username']
    password = data['password']

    users = load_users()
    for user in users:
        if user['username'] == username and user['password'] == password:
            return jsonify({'message': 'Login successful'}), 200
    return jsonify({'error': 'Invalid username or password'}), 401


# ---------- AES ENCRYPTION/DECRYPTION ----------

def aes_encrypt(text):
    key = get_random_bytes(16)
    cipher = AES.new(key, AES.MODE_CBC)
    ct_bytes = cipher.encrypt(pad(text.encode(), AES.block_size))
    encrypted_data = base64.b64encode(cipher.iv + ct_bytes).decode('utf-8')
    key_b64 = base64.b64encode(key).decode('utf-8')
    return encrypted_data, key_b64

def aes_decrypt(enc_text, key_b64):
    try:
        key = base64.b64decode(key_b64)
        enc = base64.b64decode(enc_text)
        iv = enc[:16]
        ct = enc[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        pt = unpad(cipher.decrypt(ct), AES.block_size)
        return pt.decode('utf-8')
    except Exception as e:
        return None


# ---------- RSA ENCRYPTION/DECRYPTION ----------

def rsa_encrypt(text):
    key = RSA.generate(2048)
    public_key = key.publickey()
    cipher = PKCS1_OAEP.new(public_key)
    ct = cipher.encrypt(text.encode())
    enc_text = base64.b64encode(ct).decode('utf-8')
    private_key_pem = key.export_key().decode('utf-8')
    return enc_text, private_key_pem

def rsa_decrypt(enc_text, private_key_pem):
    try:
        private_key = RSA.import_key(private_key_pem)
        cipher = PKCS1_OAEP.new(private_key)
        ct = base64.b64decode(enc_text)
        pt = cipher.decrypt(ct)
        return pt.decode('utf-8')
    except Exception:
        return None


# ---------- API ROUTES ----------

@app.route('/encrypt', methods=['POST'])
def encrypt():
    data = request.json
    method = data['method']
    text = data['text']

    if method == 'AES':
        encrypted, key = aes_encrypt(text)
    elif method == 'RSA':
        encrypted, key = rsa_encrypt(text)
    else:
        return jsonify({'error': 'Invalid encryption method'}), 400

    return jsonify({'encrypted': encrypted, 'key': key})

@app.route('/decrypt', methods=['POST'])
def decrypt():
    data = request.json
    method = data['method']
    text = data['text']
    key = data['key']

    if method == 'AES':
        decrypted = aes_decrypt(text, key)
    elif method == 'RSA':
        decrypted = rsa_decrypt(text, key)
    else:
        return jsonify({'error': 'Invalid decryption method'}), 400

    if decrypted is None:
        return jsonify({'error': 'Decryption failed'}), 400

    return jsonify({'original': decrypted})


# ---------- RUN SERVER ----------

if __name__ == '__main__':
    app.run(debug=True)
