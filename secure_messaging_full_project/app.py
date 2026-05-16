from flask import Flask, request, jsonify, render_template
from flask_socketio import SocketIO, join_room, emit
from flask_sqlalchemy import SQLAlchemy

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15

from dotenv import load_dotenv

import bcrypt
import jwt
import datetime
import base64
import hashlib
import os
import uuid

# ==========================================================
# Secure Real-Time Messaging System
# Flask + Socket.IO + SQLite
#
# Security Features:
# 1. bcrypt password hashing
# 2. JWT authentication
# 3. AES-256-GCM message encryption
# 4. SHA-512 hash verification
# 5. RSA digital signature
# 6. Encrypted database message storage
# 7. Sender/receiver separation
# 8. Login attempt limit
# 9. Message UUID replay-protection field
# 10. Database proof page
#
# Important:
# RSA private key is NOT stored in the database.
# It is kept temporarily in server memory for classroom/demo use.
# ==========================================================

load_dotenv()

app = Flask(__name__)

app.config["SECRET_KEY"] = os.getenv("SECRET_KEY")

if not app.config["SECRET_KEY"]:
    raise RuntimeError("SECRET_KEY is missing. Please set it in the .env file.")

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "sqlite:///secure_chat.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
socketio = SocketIO(app, cors_allowed_origins="*", async_mode="threading")

# AES-256 key derived from SECRET_KEY.
AES_KEY = hashlib.sha256(app.config["SECRET_KEY"].encode("utf-8")).digest()

MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 5))
LOCK_MINUTES = int(os.getenv("LOCK_MINUTES", 5))
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", 6))
BCRYPT_ROUNDS = int(os.getenv("BCRYPT_ROUNDS", 12))

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"


# ==========================================================
# Temporary In-Memory Private Key Store
# ==========================================================
# Key: username_hash
# Value: RSA private key PEM
#
# This avoids storing private keys in the database.
# Limitation: keys are lost when the server restarts.
# ==========================================================

PRIVATE_KEY_STORE = {}


# ==========================================================
# Database Models
# ==========================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username_hash = db.Column(db.String(64), unique=True, nullable=False)
    username_display = db.Column(db.String(80), unique=True, nullable=False)

    password_hash = db.Column(db.String(255), nullable=False)

    # Only public key is stored in database.
    rsa_public_key = db.Column(db.Text, nullable=False)

    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


class Message(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    message_uuid = db.Column(db.String(36), unique=True, nullable=False)

    sender_hash = db.Column(db.String(64), nullable=False)
    receiver_hash = db.Column(db.String(64), nullable=False)

    sender_display = db.Column(db.String(80), nullable=False)
    receiver_display = db.Column(db.String(80), nullable=False)

    encrypted_message = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.Text, nullable=False)
    aes_tag = db.Column(db.Text, nullable=False)

    plaintext_sha512_hash = db.Column(db.String(128), nullable=False)
    digital_signature = db.Column(db.Text, nullable=False)

    created_at = db.Column(db.DateTime, default=datetime.datetime.utcnow)


with app.app_context():
    db.create_all()


# ==========================================================
# Helper Functions
# ==========================================================

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"))


def identity_hash(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def hash_password(password: str) -> str:
    password_bytes = password.encode("utf-8")
    salt = bcrypt.gensalt(rounds=BCRYPT_ROUNDS)
    return bcrypt.hashpw(password_bytes, salt).decode("utf-8")


def verify_password(password: str, password_hash: str) -> bool:
    return bcrypt.checkpw(
        password.encode("utf-8"),
        password_hash.encode("utf-8")
    )


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode("utf-8")
    public_key = key.publickey().export_key().decode("utf-8")
    return private_key, public_key


def create_token(username: str) -> str:
    payload = {
        "username": username,
        "exp": datetime.datetime.utcnow() + datetime.timedelta(hours=JWT_EXPIRE_HOURS)
    }

    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def verify_token(token: str):
    try:
        decoded = jwt.decode(
            token,
            app.config["SECRET_KEY"],
            algorithms=["HS256"]
        )
        return decoded.get("username")
    except Exception:
        return None


def sha512_hash(message: str) -> str:
    return hashlib.sha512(message.encode("utf-8")).hexdigest()


def aes_encrypt(message: str):
    cipher = AES.new(AES_KEY, AES.MODE_GCM)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))

    return {
        "encrypted_message": b64e(ciphertext),
        "nonce": b64e(cipher.nonce),
        "aes_tag": b64e(tag)
    }


def aes_decrypt(encrypted_message: str, nonce: str, aes_tag: str) -> str:
    cipher = AES.new(AES_KEY, AES.MODE_GCM, nonce=b64d(nonce))
    plaintext = cipher.decrypt_and_verify(
        b64d(encrypted_message),
        b64d(aes_tag)
    )
    return plaintext.decode("utf-8")


def sign_message(message: str, private_key_pem: str) -> str:
    private_key = RSA.import_key(private_key_pem)
    digest = SHA512.new(message.encode("utf-8"))
    signature = pkcs1_15.new(private_key).sign(digest)
    return b64e(signature)


def verify_signature(message: str, signature_b64: str, public_key_pem: str) -> bool:
    try:
        public_key = RSA.import_key(public_key_pem)
        digest = SHA512.new(message.encode("utf-8"))
        pkcs1_15.new(public_key).verify(digest, b64d(signature_b64))
        return True
    except Exception:
        return False


def decrypt_and_verify_message(message_row: Message):
    sender = User.query.filter_by(
        username_display=message_row.sender_display
    ).first()

    if not sender:
        return None, False, False, "Sender public key not found"

    try:
        decrypted_text = aes_decrypt(
            message_row.encrypted_message,
            message_row.nonce,
            message_row.aes_tag
        )
    except Exception:
        return None, False, False, "AES-GCM decryption failed or message was tampered"

    hash_ok = sha512_hash(decrypted_text) == message_row.plaintext_sha512_hash

    signature_ok = verify_signature(
        decrypted_text,
        message_row.digital_signature,
        sender.rsa_public_key
    )

    if hash_ok and signature_ok:
        return decrypted_text, True, True, "Verified"

    if not hash_ok:
        return decrypted_text, False, signature_ok, "SHA-512 hash mismatch"

    return decrypted_text, hash_ok, False, "Digital signature invalid"


def is_account_locked(user: User) -> bool:
    if user.locked_until and user.locked_until > datetime.datetime.utcnow():
        return True
    return False


def reset_login_attempts(user: User):
    user.failed_attempts = 0
    user.locked_until = None
    db.session.commit()


def register_failed_login(user: User):
    user.failed_attempts += 1

    if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
        user.locked_until = datetime.datetime.utcnow() + datetime.timedelta(
            minutes=LOCK_MINUTES
        )

    db.session.commit()


# ==========================================================
# Page Routes
# ==========================================================

@app.route("/")
def index():
    return render_template("index.html")


@app.route("/debug-db")
def debug_db_page():
    return render_template("debug_db.html")


# ==========================================================
# API Routes
# ==========================================================

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json() or {}

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400

    if len(password) < 6:
        return jsonify({"error": "Password must be at least 6 characters"}), 400

    existing_user = User.query.filter_by(username_display=username).first()

    if existing_user:
        return jsonify({"error": "User already exists"}), 400

    private_key, public_key = generate_rsa_keys()
    username_hash = identity_hash(username)

    # Private key is stored only in temporary server memory.
    PRIVATE_KEY_STORE[username_hash] = private_key

    user = User(
        username_hash=username_hash,
        username_display=username,
        password_hash=hash_password(password),
        rsa_public_key=public_key
    )

    db.session.add(user)
    db.session.commit()

    return jsonify({
        "message": "Registration successful. RSA private key is not stored in database. Now login."
    }), 201


@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json() or {}

    username = (data.get("username") or "").strip()
    password = data.get("password") or ""

    user = User.query.filter_by(username_display=username).first()

    if not user:
        return jsonify({"error": "Invalid username or password"}), 401

    if is_account_locked(user):
        locked_until = user.locked_until.strftime("%Y-%m-%d %H:%M:%S")
        return jsonify({
            "error": f"Account temporarily locked until {locked_until}"
        }), 403

    if not verify_password(password, user.password_hash):
        register_failed_login(user)

        remaining = MAX_LOGIN_ATTEMPTS - user.failed_attempts

        if remaining <= 0:
            return jsonify({
                "error": f"Too many failed attempts. Account locked for {LOCK_MINUTES} minutes."
            }), 403

        return jsonify({
            "error": f"Invalid username or password. Attempts left: {remaining}"
        }), 401

    reset_login_attempts(user)

    return jsonify({
        "message": "Login successful",
        "token": create_token(username),
        "username": username
    })


@app.route("/api/users", methods=["GET"])
def get_users():
    users = User.query.with_entities(
        User.username_display
    ).order_by(User.username_display.asc()).all()

    return jsonify({
        "users": [u.username_display for u in users]
    })


@app.route("/api/inbox", methods=["GET"])
def inbox():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    username = verify_token(token)

    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    rows = Message.query.filter_by(
        receiver_display=username
    ).order_by(Message.created_at.asc()).all()

    messages = []

    for m in rows:
        decrypted, hash_ok, signature_ok, status = decrypt_and_verify_message(m)

        messages.append({
            "id": m.id,
            "message_uuid": m.message_uuid,
            "direction": "received",
            "sender": m.sender_display,
            "receiver": m.receiver_display,
            "decrypted_message": decrypted,
            "encrypted_message": m.encrypted_message,
            "sha512_hash": m.plaintext_sha512_hash,
            "hash_ok": hash_ok,
            "signature_ok": signature_ok,
            "status": status,
            "created_at": m.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })

    return jsonify({"messages": messages})


@app.route("/api/sent", methods=["GET"])
def sent():
    token = request.headers.get("Authorization", "").replace("Bearer ", "")
    username = verify_token(token)

    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    rows = Message.query.filter_by(
        sender_display=username
    ).order_by(Message.created_at.asc()).all()

    messages = []

    for m in rows:
        messages.append({
            "id": m.id,
            "message_uuid": m.message_uuid,
            "direction": "sent",
            "sender": m.sender_display,
            "receiver": m.receiver_display,
            "encrypted_message": m.encrypted_message,
            "sha512_hash": m.plaintext_sha512_hash,
            "created_at": m.created_at.strftime("%Y-%m-%d %H:%M:%S")
        })

    return jsonify({"messages": messages})


# ==========================================================
# Debug / Database Proof APIs
# ==========================================================

@app.route("/api/debug/users", methods=["GET"])
def debug_users():
    users = User.query.order_by(User.id.asc()).all()

    return jsonify({
        "note": "Plaintext password is not stored. bcrypt hash is stored. RSA private key is not stored in the database.",
        "users": [
            {
                "id": u.id,
                "username_display": u.username_display,
                "username_hash": u.username_hash,
                "password_hash": u.password_hash,
                "failed_attempts": u.failed_attempts,
                "locked_until": (
                    u.locked_until.strftime("%Y-%m-%d %H:%M:%S")
                    if u.locked_until else None
                ),
                "rsa_public_key_start": u.rsa_public_key[:80] + "...",
                "private_key_storage_status": "Not stored in database"
            }
            for u in users
        ]
    })


@app.route("/api/debug/messages", methods=["GET"])
def debug_messages():
    rows = Message.query.order_by(Message.id.asc()).all()

    return jsonify({
        "note": "Plaintext message is not stored in the database.",
        "messages": [
            {
                "id": m.id,
                "message_uuid": m.message_uuid,
                "sender_hash": m.sender_hash,
                "receiver_hash": m.receiver_hash,
                "sender_display": m.sender_display,
                "receiver_display": m.receiver_display,
                "encrypted_message": m.encrypted_message,
                "nonce": m.nonce,
                "aes_tag": m.aes_tag,
                "plaintext_sha512_hash": m.plaintext_sha512_hash,
                "digital_signature_start": m.digital_signature[:80] + "...",
                "created_at": m.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            for m in rows
        ]
    })


# ==========================================================
# Socket.IO Events
# ==========================================================

@socketio.on("join")
def socket_join(data):
    username = verify_token(data.get("token"))

    if not username:
        emit("auth_error", {"error": "Invalid token"})
        return

    join_room(username)

    emit("joined", {
        "message": f"{username} joined secure room"
    })


@socketio.on("send_message")
def socket_send_message(data):
    sender = verify_token(data.get("token"))

    if not sender:
        emit("send_error", {"error": "Invalid token"})
        return

    receiver = (data.get("receiver") or "").strip()
    plaintext = data.get("message") or ""

    if not receiver or not plaintext:
        emit("send_error", {"error": "Receiver and message are required"})
        return

    sender_user = User.query.filter_by(username_display=sender).first()
    receiver_user = User.query.filter_by(username_display=receiver).first()

    if not sender_user:
        emit("send_error", {"error": "Sender user not found"})
        return

    if not receiver_user:
        emit("send_error", {"error": "Receiver user not found"})
        return

    sender_private_key = PRIVATE_KEY_STORE.get(sender_user.username_hash)

    if not sender_private_key:
        emit("send_error", {
            "error": "Sender private key is not available in server memory. Please create a new account after starting the server."
        })
        return

    encrypted = aes_encrypt(plaintext)
    message_hash = sha512_hash(plaintext)
    signature = sign_message(plaintext, sender_private_key)

    msg = Message(
        message_uuid=str(uuid.uuid4()),
        sender_hash=identity_hash(sender),
        receiver_hash=identity_hash(receiver),
        sender_display=sender,
        receiver_display=receiver,
        encrypted_message=encrypted["encrypted_message"],
        nonce=encrypted["nonce"],
        aes_tag=encrypted["aes_tag"],
        plaintext_sha512_hash=message_hash,
        digital_signature=signature
    )

    db.session.add(msg)
    db.session.commit()

    decrypted, hash_ok, signature_ok, status = decrypt_and_verify_message(msg)

    receiver_payload = {
        "id": msg.id,
        "message_uuid": msg.message_uuid,
        "direction": "received",
        "sender": sender,
        "receiver": receiver,
        "decrypted_message": decrypted,
        "encrypted_message": msg.encrypted_message,
        "sha512_hash": msg.plaintext_sha512_hash,
        "hash_ok": hash_ok,
        "signature_ok": signature_ok,
        "status": status,
        "created_at": msg.created_at.strftime("%Y-%m-%d %H:%M:%S")
    }

    sender_payload = {
        "id": msg.id,
        "message_uuid": msg.message_uuid,
        "direction": "sent",
        "sender": sender,
        "receiver": receiver,
        "encrypted_message": msg.encrypted_message,
        "sha512_hash": msg.plaintext_sha512_hash,
        "created_at": msg.created_at.strftime("%Y-%m-%d %H:%M:%S")
    }

    emit("receive_message", receiver_payload, to=receiver)
    emit("sent_message", sender_payload, to=sender)


if __name__ == "__main__":
    print(f"Secure Chat running at: http://{HOST}:{PORT}")
    print(f"Database demo page: http://{HOST}:{PORT}/debug-db")
    socketio.run(app, host=HOST, port=PORT, debug=FLASK_DEBUG)