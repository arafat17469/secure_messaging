from flask import Flask, request, jsonify, render_template, send_file
from flask_socketio import SocketIO, join_room, emit
from flask_cors import CORS
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy import inspect, or_, text
from sqlalchemy.exc import IntegrityError
from werkzeug.exceptions import HTTPException
from werkzeug.utils import secure_filename

from Crypto.Cipher import AES
from Crypto.Hash import SHA512
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15, pss

from dotenv import load_dotenv

import bcrypt
import jwt
import datetime
import base64
import binascii
import hashlib
import hmac
import io
import os
import re
import secrets
import threading
import time
import uuid
from collections import defaultdict, deque


def utc_now() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)


def utc_from_timestamp(timestamp: float) -> datetime.datetime:
    return datetime.datetime.fromtimestamp(
        timestamp, datetime.timezone.utc
    ).replace(tzinfo=None)

# ==========================================================
# Badri 313
# Flask + Socket.IO + SQLite
#
# Security Features:
# 1. Salted PBKDF2-HMAC-SHA512 password hashing
# 2. JWT authentication with issuer/audience/JTI
# 3. AES-256-GCM message encryption
# 4. SHA-512 hash verification
# 5. RSA-PSS digital signature
# 6. Encrypted database message storage
# 7. Sender/receiver separation
# 8. Login attempt limit
# 9. Message UUID replay-protection field
# 10. Rate limits, security headers, and database proof page
#
# Important:
# RSA private keys are encrypted before database storage and cached in memory.
# ==========================================================

load_dotenv()

app = Flask(__name__)


def load_secret_key() -> str:
    configured_secret = os.getenv("SECRET_KEY")
    if configured_secret:
        return configured_secret

    os.makedirs(app.instance_path, exist_ok=True)
    local_secret_path = os.path.join(app.instance_path, "secret.key")

    if os.path.exists(local_secret_path):
        with open(local_secret_path, "r", encoding="utf-8") as secret_file:
            return secret_file.read().strip()

    generated_secret = secrets.token_urlsafe(48)
    with open(local_secret_path, "w", encoding="utf-8") as secret_file:
        secret_file.write(generated_secret)

    print(
        "WARNING: SECRET_KEY was missing. A local development key was created "
        f"at {local_secret_path}. For production, set SECRET_KEY in .env."
    )
    return generated_secret


app.config["SECRET_KEY"] = load_secret_key()


def load_private_key_kek() -> bytes:
    """Load a dedicated 256-bit key-encryption key, separate from JWT secrets."""
    configured_key = os.getenv("PRIVATE_KEY_KEK", "").strip()
    if configured_key:
        try:
            padded_key = configured_key + "=" * (-len(configured_key) % 4)
            decoded_key = base64.urlsafe_b64decode(padded_key.encode("ascii"))
        except Exception as error:
            raise RuntimeError(
                "PRIVATE_KEY_KEK must be URL-safe base64 for exactly 32 bytes"
            ) from error

        if len(decoded_key) != 32:
            raise RuntimeError(
                "PRIVATE_KEY_KEK must decode to exactly 32 bytes"
            )
        return decoded_key

    os.makedirs(app.instance_path, exist_ok=True)
    local_kek_path = os.path.join(app.instance_path, "private_key.kek")

    if os.path.exists(local_kek_path):
        with open(local_kek_path, "rb") as key_file:
            local_key = key_file.read()
        if len(local_key) != 32:
            raise RuntimeError(
                f"Invalid private-key KEK file: {local_kek_path}"
            )
        return local_key

    generated_key = secrets.token_bytes(32)
    with open(local_kek_path, "wb") as key_file:
        key_file.write(generated_key)

    print(
        "WARNING: PRIVATE_KEY_KEK was missing. A dedicated local key was "
        f"created at {local_kek_path}. Back it up securely for production."
    )
    return generated_key


PRIVATE_KEY_WRAP_KEY = load_private_key_kek()


def load_message_encryption_key() -> bytes:
    """Load the independent AES-256 key used for new message ciphertext."""
    configured_key = os.getenv("MESSAGE_ENCRYPTION_KEY", "").strip()
    if configured_key:
        try:
            padded_key = configured_key + "=" * (-len(configured_key) % 4)
            decoded_key = base64.urlsafe_b64decode(padded_key.encode("ascii"))
        except Exception as error:
            raise RuntimeError(
                "MESSAGE_ENCRYPTION_KEY must be URL-safe base64 for 32 bytes"
            ) from error
        if len(decoded_key) != 32:
            raise RuntimeError(
                "MESSAGE_ENCRYPTION_KEY must decode to exactly 32 bytes"
            )
        return decoded_key

    os.makedirs(app.instance_path, exist_ok=True)
    local_key_path = os.path.join(app.instance_path, "message_encryption.key")
    if os.path.exists(local_key_path):
        with open(local_key_path, "rb") as key_file:
            local_key = key_file.read()
        if len(local_key) != 32:
            raise RuntimeError(f"Invalid message key file: {local_key_path}")
        return local_key

    generated_key = secrets.token_bytes(32)
    with open(local_key_path, "wb") as key_file:
        key_file.write(generated_key)
    print(
        "WARNING: MESSAGE_ENCRYPTION_KEY was missing. A local key was created "
        f"at {local_key_path}. Back it up securely for production."
    )
    return generated_key


MESSAGE_AES_KEY = load_message_encryption_key()
MESSAGE_HMAC_KEY = hmac.new(
    MESSAGE_AES_KEY,
    b"badri-313-message-integrity-v2",
    hashlib.sha512
).digest()

app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv(
    "DATABASE_URL",
    "sqlite:///secure_chat.db"
)

app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)

LOCAL_DEV_PORTS = (3000, 5000, 5001, 5173, 5500, 5501, 8000, 8080)
LOCAL_DEV_CONNECT_SOURCES = [
    source
    for port in LOCAL_DEV_PORTS
    for source in (
        f"http://127.0.0.1:{port}",
        f"http://localhost:{port}",
        f"ws://127.0.0.1:{port}",
        f"ws://localhost:{port}"
    )
]
CORS_ALLOWED_ORIGINS_ENV = os.getenv("CORS_ALLOWED_ORIGINS", "*").strip()
SOCKET_MAX_HTTP_BUFFER_SIZE = int(os.getenv("MAX_JSON_BYTES", 262144))

if CORS_ALLOWED_ORIGINS_ENV == "*":
    CORS_ALLOWED_ORIGINS = "*"
elif CORS_ALLOWED_ORIGINS_ENV:
    CORS_ALLOWED_ORIGINS = [
        origin.strip()
        for origin in CORS_ALLOWED_ORIGINS_ENV.split(",")
        if origin.strip()
    ]
else:
    CORS_ALLOWED_ORIGINS = "*"

CORS_SUPPORTS_CREDENTIALS = CORS_ALLOWED_ORIGINS != "*"

socketio = SocketIO(
    app,
    cors_allowed_origins=CORS_ALLOWED_ORIGINS,
    async_mode="threading",
    max_http_buffer_size=SOCKET_MAX_HTTP_BUFFER_SIZE
)

# Apply CORS to all regular Flask routes
CORS(app, origins=CORS_ALLOWED_ORIGINS, supports_credentials=CORS_SUPPORTS_CREDENTIALS)


# Compatibility key for version-1 rows; new messages use an independent key.
LEGACY_AES_KEY = hashlib.sha256(
    app.config["SECRET_KEY"].encode("utf-8")
).digest()

MAX_LOGIN_ATTEMPTS = int(os.getenv("MAX_LOGIN_ATTEMPTS", 10))
LOCK_MINUTES = int(os.getenv("LOCK_MINUTES", 5))
JWT_EXPIRE_HOURS = int(os.getenv("JWT_EXPIRE_HOURS", 6))
JWT_ISSUER = os.getenv("JWT_ISSUER", "secure-messaging")
JWT_AUDIENCE = os.getenv("JWT_AUDIENCE", "secure-messaging-users")
PASSWORD_HASH_SCHEME = "pbkdf2_sha512"
PASSWORD_HASH_ITERATIONS = int(os.getenv("PASSWORD_HASH_ITERATIONS", 220000))
PASSWORD_SALT_BYTES = 16
PASSWORD_DERIVED_KEY_BYTES = 64
MAX_STORED_PASSWORD_ITERATIONS = 5_000_000
if not 1 <= PASSWORD_HASH_ITERATIONS <= MAX_STORED_PASSWORD_ITERATIONS:
    raise RuntimeError(
        "PASSWORD_HASH_ITERATIONS must be between 1 and 5,000,000"
    )
MIN_PASSWORD_LENGTH = int(os.getenv("MIN_PASSWORD_LENGTH", 8))
MAX_PASSWORD_LENGTH = int(os.getenv("MAX_PASSWORD_LENGTH", 128))
PASSWORD_REQUIRE_COMPLEXITY = (
    os.getenv("PASSWORD_REQUIRE_COMPLEXITY", "False").lower() == "true"
)
MAX_MESSAGE_CHARS = int(os.getenv("MAX_MESSAGE_CHARS", 2000))
MAX_JSON_BYTES = SOCKET_MAX_HTTP_BUFFER_SIZE
MAX_PROFILE_IMAGE_BYTES = int(os.getenv("MAX_PROFILE_IMAGE_BYTES", 2 * 1024 * 1024))
MAX_ATTACHMENT_BYTES = int(os.getenv("MAX_ATTACHMENT_BYTES", 15 * 1024 * 1024))
ALLOWED_PROFILE_IMAGE_TYPES = {"image/jpeg", "image/png", "image/webp", "image/gif"}
ALLOWED_ATTACHMENT_PREFIXES = ("image/", "audio/", "video/")
ALLOWED_ATTACHMENT_TYPES = {
    "application/pdf",
    "application/zip",
    "application/x-zip-compressed",
    "application/msword",
    "application/vnd.openxmlformats-officedocument.wordprocessingml.document",
    "application/vnd.ms-excel",
    "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
    "text/plain",
    "text/csv"
}
RATE_LIMIT_WINDOW_SECONDS = int(os.getenv("RATE_LIMIT_WINDOW_SECONDS", 60))
REGISTER_RATE_LIMIT = int(os.getenv("REGISTER_RATE_LIMIT", 100))
LOGIN_RATE_LIMIT = int(os.getenv("LOGIN_RATE_LIMIT", 100))
MESSAGE_RATE_LIMIT = int(os.getenv("MESSAGE_RATE_LIMIT", 300))
API_READ_RATE_LIMIT = int(os.getenv("API_READ_RATE_LIMIT", 600))
DEMO_DB_VIEW_ENABLED = os.getenv("DEMO_DB_VIEW_ENABLED", "False").lower() == "true"
RELAX_SECURITY_HEADERS = os.getenv("RELAX_SECURITY_HEADERS", "False").lower() == "true"
TRUST_PROXY_HEADERS = os.getenv("TRUST_PROXY_HEADERS", "False").lower() == "true"
USERNAME_RE = re.compile(r"^[A-Za-z0-9_.-]{3,80}$")
CLIENT_MESSAGE_ID_RE = re.compile(r"^[A-Za-z0-9_-]{1,80}$")

HOST = os.getenv("HOST", "127.0.0.1")
PORT = int(os.getenv("PORT", 5000))
FLASK_DEBUG = os.getenv("FLASK_DEBUG", "False").lower() == "true"


# ==========================================================
# In-Memory Private Key Cache and Presence State
# ==========================================================
# Key: username_hash
# Value: RSA private key PEM
#
# Private keys are also stored as AES-256-GCM wrapped ciphertext in SQLite so
# users can continue signing after a server restart. Plaintext keys live only
# in this process cache while the app is running.
# ==========================================================

PRIVATE_KEY_STORE = {}
TOKEN_BLOCKLIST = set()
RATE_LIMIT_BUCKETS = defaultdict(deque)
SOCKET_USERS = {}
ONLINE_USER_COUNTS = defaultdict(int)
PRESENCE_LOCK = threading.Lock()
RATE_LIMIT_LOCK = threading.Lock()


# ==========================================================
# Database Models
# ==========================================================

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)

    username_hash = db.Column(db.String(64), unique=True, nullable=False)
    username_display = db.Column(db.String(80), unique=True, nullable=False)

    password_hash = db.Column(db.String(255), nullable=False)

    # Current public key plus a pointer to a versioned encrypted signing key.
    rsa_public_key = db.Column(db.Text, nullable=False)
    rsa_private_key_encrypted = db.Column(db.Text, nullable=True)
    rsa_private_key_nonce = db.Column(db.Text, nullable=True)
    rsa_private_key_tag = db.Column(db.Text, nullable=True)
    active_signing_key_id = db.Column(db.Integer, nullable=True)

    failed_attempts = db.Column(db.Integer, default=0)
    locked_until = db.Column(db.DateTime, nullable=True)

    profile_image = db.Column(db.Text, nullable=True)
    profile_image_mime = db.Column(db.String(100), nullable=True)
    profile_bio = db.Column(db.String(160), nullable=False, default="")

    created_at = db.Column(db.DateTime, default=utc_now)


class SigningKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_hash = db.Column(db.String(64), nullable=False, index=True)
    public_key = db.Column(db.Text, nullable=False)
    wrapped_private_key = db.Column(db.Text, nullable=True)
    nonce = db.Column(db.Text, nullable=True)
    aes_tag = db.Column(db.Text, nullable=True)
    kek_version = db.Column(db.String(32), nullable=False, default="v1")
    status = db.Column(db.String(20), nullable=False, default="active")
    created_at = db.Column(db.DateTime, default=utc_now)


class RevokedToken(db.Model):
    jti = db.Column(db.String(36), primary_key=True)
    expires_at = db.Column(db.DateTime, nullable=False, index=True)
    revoked_at = db.Column(
        db.DateTime,
        nullable=False,
        default=utc_now
    )


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
    sender_public_key = db.Column(db.Text, nullable=True)
    signing_key_id = db.Column(db.Integer, nullable=True)
    security_version = db.Column(db.Integer, nullable=False, default=2)
    deleted_at = db.Column(db.DateTime, nullable=True)

    created_at = db.Column(db.DateTime, default=utc_now)


class Attachment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    message_uuid = db.Column(db.String(36), unique=True, nullable=False, index=True)
    filename = db.Column(db.String(255), nullable=False)
    mime_type = db.Column(db.String(160), nullable=False)
    size = db.Column(db.Integer, nullable=False)
    encrypted_data = db.Column(db.Text, nullable=False)
    nonce = db.Column(db.Text, nullable=False)
    aes_tag = db.Column(db.Text, nullable=False)
    content_sha512_hash = db.Column(db.String(128), nullable=False)
    digital_signature = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=utc_now)


def ensure_schema_compatibility():
    """Add columns introduced after the original demo without losing data."""
    inspector = inspect(db.engine)
    user_columns = {column["name"] for column in inspector.get_columns("user")}
    message_columns = {
        column["name"] for column in inspector.get_columns("message")
    }

    user_migrations = {
        "rsa_private_key_encrypted": "TEXT",
        "rsa_private_key_nonce": "TEXT",
        "rsa_private_key_tag": "TEXT",
        "active_signing_key_id": "INTEGER",
        "profile_image": "TEXT",
        "profile_image_mime": "VARCHAR(100)",
        "profile_bio": "VARCHAR(160) NOT NULL DEFAULT ''"
    }
    message_migrations = {
        "sender_public_key": "TEXT",
        "signing_key_id": "INTEGER",
        "security_version": "INTEGER NOT NULL DEFAULT 1",
        "deleted_at": "DATETIME"
    }

    with db.engine.begin() as connection:
        for column_name, column_type in user_migrations.items():
            if column_name not in user_columns:
                connection.execute(text(
                    f'ALTER TABLE "user" ADD COLUMN {column_name} {column_type}'
                ))

        for column_name, column_type in message_migrations.items():
            if column_name not in message_columns:
                connection.execute(text(
                    f"ALTER TABLE message ADD COLUMN {column_name} {column_type}"
                ))

        # Preserve the key that verifies every pre-migration message before a
        # user's current key is ever rotated/recovered.
        connection.execute(text(
            """
            UPDATE message
            SET sender_public_key = (
                SELECT rsa_public_key
                FROM "user"
                WHERE "user".username_hash = message.sender_hash
            )
            WHERE sender_public_key IS NULL
            """
        ))

    # Link old rows to a verify-only key. A new active key will be created at
    # the user's next successful login; historic signatures keep their key.
    for user in User.query.all():
        legacy_key = SigningKey.query.filter_by(
            user_hash=user.username_hash,
            public_key=user.rsa_public_key
        ).order_by(SigningKey.id.asc()).first()

        if not legacy_key:
            legacy_key = SigningKey(
                user_hash=user.username_hash,
                public_key=user.rsa_public_key,
                status="verify_only",
                kek_version="legacy"
            )
            db.session.add(legacy_key)
            db.session.flush()

        Message.query.filter_by(
            sender_hash=user.username_hash,
            signing_key_id=None
        ).update({
            Message.signing_key_id: legacy_key.id,
            Message.sender_public_key: user.rsa_public_key
        }, synchronize_session=False)

    db.session.commit()


with app.app_context():
    db.create_all()
    ensure_schema_compatibility()


# ==========================================================
# HTTP Security Hooks
# ==========================================================

@app.before_request
def reject_large_json_payloads():
    if request.method in {"POST", "PUT", "PATCH"}:
        content_length = request.content_length or 0
        upload_limit = (
            MAX_ATTACHMENT_BYTES + 64 * 1024
            if request.path == "/api/messages/attachments"
            else MAX_PROFILE_IMAGE_BYTES + 64 * 1024
            if request.path == "/api/profile/photo"
            else MAX_JSON_BYTES
        )
        if content_length > upload_limit:
            return jsonify({"error": "Request body is too large"}), 413


@app.after_request
def add_security_headers(response):
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "SAMEORIGIN" if RELAX_SECURITY_HEADERS else "DENY"
    response.headers["Referrer-Policy"] = "no-referrer"
    response.headers["Permissions-Policy"] = "camera=(self), microphone=(self), geolocation=()"
    response.headers["Cache-Control"] = "no-cache" if RELAX_SECURITY_HEADERS else "no-store"

    if not RELAX_SECURITY_HEADERS:
        local_connect_sources = " ".join(LOCAL_DEV_CONNECT_SOURCES)
        response.headers["Content-Security-Policy"] = (
            "default-src 'self'; "
            "script-src 'self' 'unsafe-inline' https://cdn.socket.io; "
            "style-src 'self' 'unsafe-inline'; "
            "img-src 'self' https://i.pravatar.cc data: blob:; "
            "media-src 'self' blob:; "
            f"connect-src 'self' {local_connect_sources} ws: wss:; "
            "base-uri 'self'; "
            "form-action 'self'"
        )

    return response


@app.errorhandler(HTTPException)
def handle_http_exception(error):
    if request.path.startswith("/api/"):
        return jsonify({
            "error": error.description or error.name
        }), error.code

    return error


@app.errorhandler(Exception)
def handle_unexpected_exception(error):
    app.logger.exception("Unhandled application error")
    db.session.rollback()

    if request.path.startswith("/api/"):
        return jsonify({
            "error": "Server error. Check the Flask terminal logs and try again."
        }), 500

    raise error


# ==========================================================
# Helper Functions
# ==========================================================

def b64e(data: bytes) -> str:
    return base64.b64encode(data).decode("utf-8")


def b64d(data: str) -> bytes:
    return base64.b64decode(data.encode("utf-8"), validate=True)


def identity_hash(value: str) -> str:
    return hashlib.sha256(value.strip().lower().encode("utf-8")).hexdigest()


def find_user_by_username(username: str):
    return User.query.filter_by(username_hash=identity_hash(username)).first()


def client_ip() -> str:
    forwarded_for = request.headers.get("X-Forwarded-For", "")
    if TRUST_PROXY_HEADERS and forwarded_for:
        return forwarded_for.split(",")[0].strip()
    return request.remote_addr or "unknown"


def rate_limit_key(scope: str, key: str) -> str:
    return f"{scope}:{key}"


def is_rate_limited(key: str, limit: int, window_seconds: int) -> bool:
    now = time.time()
    with RATE_LIMIT_LOCK:
        bucket = RATE_LIMIT_BUCKETS[key]

        while bucket and now - bucket[0] > window_seconds:
            bucket.popleft()

        if len(bucket) >= limit:
            return True

        bucket.append(now)
        return False


def rate_limit_response():
    return jsonify({"error": "Too many requests. Please wait and try again."}), 429


def get_bearer_token() -> str:
    auth_header = request.headers.get("Authorization", "")
    return auth_header.removeprefix("Bearer ").strip()


def require_auth_username():
    return verify_token(get_bearer_token())


def require_auth_user():
    user, _ = decode_token(get_bearer_token())
    return user


def password_policy_errors(password: str):
    errors = []

    if len(password) < MIN_PASSWORD_LENGTH:
        errors.append(f"Password must be at least {MIN_PASSWORD_LENGTH} characters")

    if len(password) > MAX_PASSWORD_LENGTH or len(password.encode("utf-8")) > 1024:
        errors.append(f"Password must be at most {MAX_PASSWORD_LENGTH} characters")

    if PASSWORD_REQUIRE_COMPLEXITY:
        checks = [
            (r"[a-z]", "one lowercase letter"),
            (r"[A-Z]", "one uppercase letter"),
            (r"\d", "one number"),
            (r"[^A-Za-z0-9]", "one symbol")
        ]
        missing = [label for pattern, label in checks if not re.search(pattern, password)]

        if missing:
            errors.append("Password must include " + ", ".join(missing))

    return errors


def hash_password(password: str) -> str:
    salt = secrets.token_bytes(PASSWORD_SALT_BYTES)
    derived_key = hashlib.pbkdf2_hmac(
        "sha512",
        password.encode("utf-8"),
        salt,
        PASSWORD_HASH_ITERATIONS,
        dklen=PASSWORD_DERIVED_KEY_BYTES
    )
    return "$".join((
        PASSWORD_HASH_SCHEME,
        str(PASSWORD_HASH_ITERATIONS),
        b64e(salt),
        b64e(derived_key)
    ))


def verify_password(password: str, password_hash: str) -> bool:
    password_bytes = password.encode("utf-8")
    if len(password) > MAX_PASSWORD_LENGTH or len(password_bytes) > 1024:
        return False

    if password_hash.startswith(f"{PASSWORD_HASH_SCHEME}$"):
        try:
            scheme, iterations_text, salt_text, expected_text = password_hash.split("$")
            iterations = int(iterations_text)
            if scheme != PASSWORD_HASH_SCHEME:
                return False
            if iterations < 1 or iterations > MAX_STORED_PASSWORD_ITERATIONS:
                return False

            salt = b64d(salt_text)
            expected = b64d(expected_text)
            if len(salt) < 16 or len(expected) != PASSWORD_DERIVED_KEY_BYTES:
                return False

            actual = hashlib.pbkdf2_hmac(
                "sha512",
                password_bytes,
                salt,
                iterations,
                dklen=len(expected)
            )
            return hmac.compare_digest(actual, expected)
        except (TypeError, ValueError, binascii.Error):
            return False

    # One-time compatibility path for accounts made by earlier releases.
    if password_hash.startswith(("$2a$", "$2b$", "$2y$")):
        if len(password_bytes) > 72:
            return False
        try:
            return bcrypt.checkpw(password_bytes, password_hash.encode("utf-8"))
        except (TypeError, ValueError):
            return False

    return False


def password_hash_needs_upgrade(password_hash: str) -> bool:
    if not password_hash.startswith(f"{PASSWORD_HASH_SCHEME}$"):
        return True
    try:
        return int(password_hash.split("$", 2)[1]) < PASSWORD_HASH_ITERATIONS
    except (IndexError, ValueError):
        return True


def password_hash_label(password_hash: str) -> str:
    if password_hash.startswith(f"{PASSWORD_HASH_SCHEME}$"):
        return "PBKDF2-HMAC-SHA512"
    if password_hash.startswith(("$2a$", "$2b$", "$2y$")):
        return "bcrypt (legacy; upgrades on login)"
    return "Unknown"


DUMMY_PASSWORD_HASH = hash_password(secrets.token_urlsafe(32))


def generate_rsa_keys():
    key = RSA.generate(2048)
    private_key = key.export_key().decode("utf-8")
    public_key = key.publickey().export_key().decode("utf-8")
    return private_key, public_key


def signing_key_aad(user_hash: str, key_id: int, kek_version: str) -> bytes:
    return (
        f"badri-313-signing-key|{user_hash}|{key_id}|{kek_version}"
    ).encode("utf-8")


def wrap_signing_private_key(
    private_key_pem: str,
    user_hash: str,
    key_id: int,
    kek_version: str = "v1"
):
    cipher = AES.new(PRIVATE_KEY_WRAP_KEY, AES.MODE_GCM)
    cipher.update(signing_key_aad(user_hash, key_id, kek_version))
    ciphertext, tag = cipher.encrypt_and_digest(private_key_pem.encode("utf-8"))
    return b64e(ciphertext), b64e(cipher.nonce), b64e(tag)


def unwrap_signing_private_key(signing_key: SigningKey) -> str:
    if not all((
        signing_key.wrapped_private_key,
        signing_key.nonce,
        signing_key.aes_tag
    )):
        raise ValueError("Signing key has no wrapped private material")

    cipher = AES.new(
        PRIVATE_KEY_WRAP_KEY,
        AES.MODE_GCM,
        nonce=b64d(signing_key.nonce)
    )
    cipher.update(signing_key_aad(
        signing_key.user_hash,
        signing_key.id,
        signing_key.kek_version
    ))
    private_key = cipher.decrypt_and_verify(
        b64d(signing_key.wrapped_private_key),
        b64d(signing_key.aes_tag)
    ).decode("utf-8")

    derived_public_key = (
        RSA.import_key(private_key).publickey().export_key().decode("utf-8")
    )
    if not hmac.compare_digest(derived_public_key, signing_key.public_key):
        raise ValueError("Wrapped signing key does not match its public key")
    return private_key


def provision_active_signing_key(user: User):
    private_key, public_key = generate_rsa_keys()
    signing_key = SigningKey(
        user_hash=user.username_hash,
        public_key=public_key,
        kek_version="v1",
        status="active"
    )
    db.session.add(signing_key)
    db.session.flush()

    wrapped, nonce, aes_tag = wrap_signing_private_key(
        private_key,
        user.username_hash,
        signing_key.id,
        signing_key.kek_version
    )
    signing_key.wrapped_private_key = wrapped
    signing_key.nonce = nonce
    signing_key.aes_tag = aes_tag
    user.active_signing_key_id = signing_key.id
    user.rsa_public_key = public_key
    PRIVATE_KEY_STORE[signing_key.id] = private_key
    return signing_key


def ensure_active_signing_key(user: User):
    signing_key = (
        db.session.get(SigningKey, user.active_signing_key_id)
        if user.active_signing_key_id else None
    )

    if signing_key and signing_key.status == "active":
        cached_key = PRIVATE_KEY_STORE.get(signing_key.id)
        if cached_key:
            return signing_key, False
        try:
            PRIVATE_KEY_STORE[signing_key.id] = unwrap_signing_private_key(
                signing_key
            )
            return signing_key, False
        except (TypeError, ValueError, binascii.Error):
            signing_key.status = "retired"

    return provision_active_signing_key(user), True


def active_private_key(user: User):
    signing_key, _ = ensure_active_signing_key(user)
    private_key = PRIVATE_KEY_STORE.get(signing_key.id)
    if not private_key:
        private_key = unwrap_signing_private_key(signing_key)
        PRIVATE_KEY_STORE[signing_key.id] = private_key
    return signing_key, private_key


def create_token(username: str) -> str:
    user = find_user_by_username(username)
    if not user:
        raise ValueError("Cannot create token for unknown user")

    now = utc_now()
    payload = {
        "username": user.username_display,
        "sub": user.username_hash,
        "jti": str(uuid.uuid4()),
        "iat": now,
        "nbf": now,
        "exp": now + datetime.timedelta(hours=JWT_EXPIRE_HOURS),
        "iss": JWT_ISSUER,
        "aud": JWT_AUDIENCE
    }

    return jwt.encode(payload, app.config["SECRET_KEY"], algorithm="HS256")


def is_token_revoked(jti: str) -> bool:
    if not jti:
        return True
    if jti in TOKEN_BLOCKLIST:
        return True
    revoked = db.session.get(RevokedToken, jti)
    if revoked:
        TOKEN_BLOCKLIST.add(jti)
        return True
    return False


def decode_token(token: str):
    try:
        decoded = jwt.decode(
            token,
            app.config["SECRET_KEY"],
            algorithms=["HS256"],
            issuer=JWT_ISSUER,
            audience=JWT_AUDIENCE,
            options={
                "require": ["exp", "iat", "nbf", "iss", "aud", "sub", "jti", "username"]
            }
        )

        if is_token_revoked(decoded.get("jti")):
            return None, None

        user = find_user_by_username(decoded.get("username", ""))
        if not user or user.username_hash != decoded.get("sub"):
            return None, None

        return user, decoded
    except Exception:
        return None, None


def verify_token(token: str):
    user, _ = decode_token(token)
    return user.username_display if user else None


def revoke_token(decoded: dict):
    jti = decoded.get("jti")
    expires_at = decoded.get("exp")
    if not jti or not expires_at:
        return

    if isinstance(expires_at, (int, float)):
        expires_at = utc_from_timestamp(expires_at)

    TOKEN_BLOCKLIST.add(jti)
    if not db.session.get(RevokedToken, jti):
        db.session.add(RevokedToken(jti=jti, expires_at=expires_at))
    RevokedToken.query.filter(
        RevokedToken.expires_at < utc_now()
    ).delete(synchronize_session=False)
    db.session.commit()


def sha512_hash(message: str) -> str:
    return hashlib.sha512(message.encode("utf-8")).hexdigest()


def message_integrity_hash(message: str, context: bytes) -> str:
    return hmac.new(
        MESSAGE_HMAC_KEY,
        context + b"\0" + message.encode("utf-8"),
        hashlib.sha512
    ).hexdigest()


def is_valid_username(username: str) -> bool:
    return bool(USERNAME_RE.fullmatch(username))


def message_security_context(message_row: Message) -> bytes:
    return (
        "badri-313-message-v2|"
        f"{message_row.message_uuid}|"
        f"{message_row.sender_hash}|"
        f"{message_row.receiver_hash}"
    ).encode("utf-8")


def aes_encrypt(message: str, context: bytes = b""):
    cipher = AES.new(MESSAGE_AES_KEY, AES.MODE_GCM)
    if context:
        cipher.update(context)
    ciphertext, tag = cipher.encrypt_and_digest(message.encode("utf-8"))

    return {
        "encrypted_message": b64e(ciphertext),
        "nonce": b64e(cipher.nonce),
        "aes_tag": b64e(tag)
    }


def aes_decrypt(
    encrypted_message: str,
    nonce: str,
    aes_tag: str,
    context: bytes = b"",
    encryption_key: bytes = MESSAGE_AES_KEY
) -> str:
    cipher = AES.new(encryption_key, AES.MODE_GCM, nonce=b64d(nonce))
    if context:
        cipher.update(context)
    plaintext = cipher.decrypt_and_verify(
        b64d(encrypted_message),
        b64d(aes_tag)
    )
    return plaintext.decode("utf-8")


def aes_encrypt_bytes(payload: bytes, context: bytes):
    cipher = AES.new(MESSAGE_AES_KEY, AES.MODE_GCM)
    cipher.update(context)
    ciphertext, tag = cipher.encrypt_and_digest(payload)
    return b64e(ciphertext), b64e(cipher.nonce), b64e(tag)


def aes_decrypt_bytes(encrypted: str, nonce: str, tag: str, context: bytes):
    cipher = AES.new(MESSAGE_AES_KEY, AES.MODE_GCM, nonce=b64d(nonce))
    cipher.update(context)
    return cipher.decrypt_and_verify(b64d(encrypted), b64d(tag))


def profile_payload(user: User):
    photo = None
    if user.profile_image and user.profile_image_mime:
        photo = f"data:{user.profile_image_mime};base64,{user.profile_image}"
    return {
        "username": user.username_display,
        "bio": user.profile_bio or "",
        "photo": photo
    }


def attachment_context(message_row: Message, attachment: Attachment) -> bytes:
    return "|".join((
        "badri-313-attachment-v1",
        message_row.message_uuid,
        message_row.sender_hash,
        message_row.receiver_hash,
        attachment.filename,
        attachment.mime_type,
        str(attachment.size)
    )).encode("utf-8")


def attachment_signature_bytes(attachment: Attachment, context: bytes) -> bytes:
    return b"\0".join((
        context,
        b64d(attachment.encrypted_data),
        b64d(attachment.nonce),
        b64d(attachment.aes_tag),
        attachment.content_sha512_hash.encode("ascii")
    ))


def decrypt_and_verify_attachment(message_row: Message, attachment: Attachment):
    context = attachment_context(message_row, attachment)
    public_key = message_row.sender_public_key
    if not public_key or not verify_signed_bytes(
        attachment_signature_bytes(attachment, context),
        attachment.digital_signature,
        public_key
    ):
        raise ValueError("Attachment signature verification failed")

    content = aes_decrypt_bytes(
        attachment.encrypted_data,
        attachment.nonce,
        attachment.aes_tag,
        context
    )
    calculated_hash = hmac.new(
        MESSAGE_HMAC_KEY,
        context + b"\0" + content,
        hashlib.sha512
    ).hexdigest()
    if not hmac.compare_digest(calculated_hash, attachment.content_sha512_hash):
        raise ValueError("Attachment hash verification failed")
    return content


def signature_bytes(message: str, context: bytes = b"") -> bytes:
    if context:
        return context + b"\0" + message.encode("utf-8")
    return message.encode("utf-8")


def encrypted_record_signature_bytes(message_row: Message) -> bytes:
    return b"\0".join((
        message_security_context(message_row),
        b64d(message_row.encrypted_message),
        b64d(message_row.nonce),
        b64d(message_row.aes_tag)
    ))


def sign_bytes(payload: bytes, private_key_pem: str) -> str:
    private_key = RSA.import_key(private_key_pem)
    return b64e(pss.new(private_key).sign(SHA512.new(payload)))


def verify_signed_bytes(
    payload: bytes,
    signature_b64: str,
    public_key_pem: str,
    allow_legacy_pkcs1: bool = False
) -> bool:
    try:
        public_key = RSA.import_key(public_key_pem)
        digest = SHA512.new(payload)
        try:
            pss.new(public_key).verify(digest, b64d(signature_b64))
            return True
        except Exception:
            if not allow_legacy_pkcs1:
                return False
            pkcs1_15.new(public_key).verify(digest, b64d(signature_b64))
            return True
    except Exception:
        return False


def sign_message(
    message: str,
    private_key_pem: str,
    context: bytes = b""
) -> str:
    return sign_bytes(signature_bytes(message, context), private_key_pem)


def verify_signature(
    message: str,
    signature_b64: str,
    public_key_pem: str,
    context: bytes = b""
) -> bool:
    return verify_signed_bytes(
        signature_bytes(message, context),
        signature_b64,
        public_key_pem,
        allow_legacy_pkcs1=True
    )


def decrypt_and_verify_message(message_row: Message):
    if message_row.deleted_at:
        return "", True, True, "Message unsent"

    signing_key = (
        db.session.get(SigningKey, message_row.signing_key_id)
        if message_row.signing_key_id else None
    )
    public_key = (
        signing_key.public_key if signing_key
        else message_row.sender_public_key
    )

    if not public_key:
        return None, False, False, "Sender public key not found"

    if signing_key and signing_key.user_hash != message_row.sender_hash:
        return None, False, False, "Signing key does not belong to sender"

    is_metadata_bound = (message_row.security_version or 1) >= 2
    context = message_security_context(message_row) if is_metadata_bound else b""

    if is_metadata_bound:
        signature_ok = verify_signed_bytes(
            encrypted_record_signature_bytes(message_row),
            message_row.digital_signature,
            public_key
        )
        if not signature_ok:
            return None, False, False, "Digital signature invalid; content quarantined"

    try:
        decrypted_text = aes_decrypt(
            message_row.encrypted_message,
            message_row.nonce,
            message_row.aes_tag,
            context,
            MESSAGE_AES_KEY if is_metadata_bound else LEGACY_AES_KEY
        )
    except Exception:
        return None, False, False, "AES-GCM decryption failed or message was tampered"

    calculated_hash = (
        message_integrity_hash(decrypted_text, context)
        if is_metadata_bound else sha512_hash(decrypted_text)
    )
    hash_ok = hmac.compare_digest(
        calculated_hash,
        message_row.plaintext_sha512_hash
    )

    if not is_metadata_bound:
        signature_ok = verify_signature(
            decrypted_text,
            message_row.digital_signature,
            public_key
        )

    if hash_ok and signature_ok:
        status = "Verified" if is_metadata_bound else "Verified legacy message"
        return decrypted_text, True, True, status

    if not hash_ok:
        return None, False, signature_ok, "SHA-512 hash mismatch; content quarantined"

    return None, hash_ok, False, "Digital signature invalid; content quarantined"


def message_payload(message_row: Message, direction: str, decrypted: str, hash_ok: bool, signature_ok: bool, status: str):
    sender = User.query.filter_by(username_hash=message_row.sender_hash).first()
    receiver = User.query.filter_by(username_hash=message_row.receiver_hash).first()
    created_at = message_row.created_at or utc_now()
    if created_at.tzinfo is None:
        created_at = created_at.replace(tzinfo=datetime.timezone.utc)

    attachment = None
    attachment_row = Attachment.query.filter_by(
        message_uuid=message_row.message_uuid
    ).first()
    if attachment_row and not message_row.deleted_at:
        attachment = {
            "filename": attachment_row.filename,
            "mime_type": attachment_row.mime_type,
            "size": attachment_row.size,
            "url": f"/api/attachments/{message_row.message_uuid}"
        }

    deleted_at = message_row.deleted_at
    if deleted_at and deleted_at.tzinfo is None:
        deleted_at = deleted_at.replace(tzinfo=datetime.timezone.utc)

    return {
        "id": message_row.id,
        "message_uuid": message_row.message_uuid,
        "direction": direction,
        "sender": sender.username_display if sender else "Unknown user",
        "receiver": receiver.username_display if receiver else "Unknown user",
        "decrypted_message": "" if message_row.deleted_at else decrypted,
        "hash_ok": hash_ok,
        "signature_ok": signature_ok,
        "status": status,
        "security_version": message_row.security_version or 1,
        "metadata_bound": (message_row.security_version or 1) >= 2,
        "created_at": created_at.isoformat().replace("+00:00", "Z"),
        "deleted": bool(message_row.deleted_at),
        "deleted_at": (
            deleted_at.isoformat().replace("+00:00", "Z")
            if deleted_at else None
        ),
        "attachment": attachment
    }


def is_account_locked(user: User) -> bool:
    if user.locked_until and user.locked_until > utc_now():
        return True
    return False


def reset_login_attempts(user: User):
    user.failed_attempts = 0
    user.locked_until = None


def register_failed_login(user: User):
    user.failed_attempts += 1

    if user.failed_attempts >= MAX_LOGIN_ATTEMPTS:
        user.locked_until = utc_now() + datetime.timedelta(
            minutes=LOCK_MINUTES
        )

    db.session.commit()


def security_status_payload(user: User):
    return {
        "authenticated_as": user.username_display,
        "password_hashing": "PBKDF2-HMAC-SHA512",
        "password_hash_iterations": PASSWORD_HASH_ITERATIONS,
        "password_policy": {
            "minimum_length": MIN_PASSWORD_LENGTH,
            "maximum_length": MAX_PASSWORD_LENGTH,
            "complexity_required": PASSWORD_REQUIRE_COMPLEXITY
        },
        "message_encryption": "AES-256-GCM",
        "message_hash": "Keyed HMAC-SHA512",
        "signature": "RSA-PSS/SHA-512 over encrypted records",
        "metadata_authentication": "AES-GCM AAD + signed sender/receiver/UUID",
        "jwt": {
            "algorithm": "HS256",
            "expires_hours": JWT_EXPIRE_HOURS,
            "issuer": JWT_ISSUER,
            "audience": JWT_AUDIENCE,
            "logout_revocation": "Persistent JTI revocation + socket disconnect"
        },
        "limits": {
            "max_message_chars": MAX_MESSAGE_CHARS,
            "max_json_bytes": MAX_JSON_BYTES,
            "message_rate_per_window": MESSAGE_RATE_LIMIT,
            "rate_window_seconds": RATE_LIMIT_WINDOW_SECONDS
        },
        "private_key_storage": "Versioned AES-256-GCM wrapped signing key"
    }


def scan_messages_for_user(user: User):
    rows = Message.query.filter(or_(
        Message.sender_hash == user.username_hash,
        Message.receiver_hash == user.username_hash
    )).order_by(Message.created_at.asc(), Message.id.asc()).all()

    messages = []
    verified = 0
    failed = 0
    legacy = 0
    received = 0
    sent_count = 0

    for message_row in rows:
        direction = (
            "sent" if message_row.sender_hash == user.username_hash
            else "received"
        )
        if direction == "sent":
            sent_count += 1
        else:
            received += 1

        decrypted, hash_ok, signature_ok, status = decrypt_and_verify_message(
            message_row
        )
        if hash_ok and signature_ok:
            verified += 1
        else:
            failed += 1
        if (message_row.security_version or 1) < 2:
            legacy += 1

        messages.append(message_payload(
            message_row,
            direction,
            decrypted,
            hash_ok,
            signature_ok,
            status
        ))

    scanned_at = datetime.datetime.now(datetime.timezone.utc).isoformat().replace(
        "+00:00", "Z"
    )
    return messages, {
        "total": len(rows),
        "verified": verified,
        "failed": failed,
        "legacy": legacy,
        "received": received,
        "sent": sent_count,
        "status": "passed" if failed == 0 else "warning",
        "scanned_at": scanned_at
    }


def create_verified_message(
    sender_user: User,
    receiver_name: str,
    plaintext: str,
    attachment_content: bytes = None,
    attachment_filename: str = "",
    attachment_mime: str = ""
):
    receiver = receiver_name.strip()
    plaintext = plaintext.strip()

    if not receiver or (not plaintext and attachment_content is None):
        return None, "Receiver and message or attachment are required"

    if len(plaintext) > MAX_MESSAGE_CHARS:
        return None, (
            f"Message is too long. Maximum {MAX_MESSAGE_CHARS} characters allowed."
        )

    if not is_valid_username(receiver):
        return None, "Receiver username is invalid"

    if sender_user.username_hash == identity_hash(receiver):
        return None, "You cannot send a message to yourself"

    receiver_user = find_user_by_username(receiver)

    if not receiver_user:
        return None, "Receiver user not found"

    try:
        signing_key, sender_private_key = active_private_key(sender_user)
    except Exception:
        app.logger.exception("Could not load sender signing key")
        db.session.rollback()
        return None, "Signing key is unavailable. Please login again."

    msg = Message(
        message_uuid=str(uuid.uuid4()),
        sender_hash=sender_user.username_hash,
        receiver_hash=receiver_user.username_hash,
        sender_display=sender_user.username_display,
        receiver_display=receiver_user.username_display,
        encrypted_message="pending",
        nonce="pending",
        aes_tag="pending",
        plaintext_sha512_hash="pending",
        digital_signature="pending",
        sender_public_key=signing_key.public_key,
        signing_key_id=signing_key.id,
        security_version=2,
        created_at=utc_now()
    )

    context = message_security_context(msg)
    encrypted = aes_encrypt(plaintext, context)
    msg.encrypted_message = encrypted["encrypted_message"]
    msg.nonce = encrypted["nonce"]
    msg.aes_tag = encrypted["aes_tag"]
    msg.plaintext_sha512_hash = message_integrity_hash(plaintext, context)
    msg.digital_signature = sign_bytes(
        encrypted_record_signature_bytes(msg),
        sender_private_key
    )

    attachment = None
    if attachment_content is not None:
        safe_filename = secure_filename(attachment_filename)[:255]
        if not safe_filename:
            return None, "Attachment filename is invalid"
        attachment = Attachment(
            message_uuid=msg.message_uuid,
            filename=safe_filename,
            mime_type=attachment_mime[:160],
            size=len(attachment_content),
            encrypted_data="pending",
            nonce="pending",
            aes_tag="pending",
            content_sha512_hash="pending",
            digital_signature="pending",
            created_at=msg.created_at
        )
        attachment_aad = attachment_context(msg, attachment)
        encrypted_data, attachment_nonce, attachment_tag = aes_encrypt_bytes(
            attachment_content,
            attachment_aad
        )
        attachment.encrypted_data = encrypted_data
        attachment.nonce = attachment_nonce
        attachment.aes_tag = attachment_tag
        attachment.content_sha512_hash = hmac.new(
            MESSAGE_HMAC_KEY,
            attachment_aad + b"\0" + attachment_content,
            hashlib.sha512
        ).hexdigest()
        attachment.digital_signature = sign_bytes(
            attachment_signature_bytes(attachment, attachment_aad),
            sender_private_key
        )

    try:
        db.session.add(msg)
        if attachment:
            db.session.add(attachment)
        db.session.commit()
    except Exception:
        app.logger.exception("Could not store message")
        db.session.rollback()
        return None, "Message could not be stored. Please try again."

    decrypted, hash_ok, signature_ok, status = decrypt_and_verify_message(msg)
    return {
        "message": msg,
        "receiver_user": receiver_user,
        "receiver_payload": message_payload(
            msg, "received", decrypted, hash_ok, signature_ok, status
        ),
        "sender_payload": message_payload(
            msg, "sent", decrypted, hash_ok, signature_ok, status
        )
    }, None


# ==========================================================
# Page Routes
# ==========================================================

@app.route("/")
def index():
    return render_template(
        "index.html",
        min_password_length=MIN_PASSWORD_LENGTH,
        max_password_length=MAX_PASSWORD_LENGTH,
        password_require_complexity=PASSWORD_REQUIRE_COMPLEXITY
    )


@app.route("/debug-db")
def debug_db_page():
    return render_template("debug_db.html")


# ==========================================================
# API Routes
# ==========================================================

@app.route("/api/health", methods=["GET"])
def health():
    return jsonify({
        "ok": True,
        "app": "Badri 313",
        "api": "ready"
    })


@app.route("/api/register", methods=["POST"])
def register():
    if is_rate_limited(
        rate_limit_key("register", client_ip()),
        REGISTER_RATE_LIMIT,
        RATE_LIMIT_WINDOW_SECONDS
    ):
        return rate_limit_response()

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required"}), 400

    username_value = data.get("username")
    password = data.get("password")
    if not isinstance(username_value, str) or not isinstance(password, str):
        return jsonify({"error": "Username and password must be text"}), 400
    username = username_value.strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if len(username) < 3:
        return jsonify({"error": "Username must be at least 3 characters"}), 400

    if not is_valid_username(username):
        return jsonify({
            "error": "Username can only contain letters, numbers, dots, underscores, and hyphens"
        }), 400

    password_errors = password_policy_errors(password)
    if password_errors:
        return jsonify({"error": ". ".join(password_errors)}), 400

    existing_user = find_user_by_username(username)

    if existing_user:
        return jsonify({"error": "User already exists"}), 400

    username_hash = identity_hash(username)

    user = User(
        username_hash=username_hash,
        username_display=username,
        password_hash=hash_password(password),
        rsa_public_key="pending"
    )

    try:
        db.session.add(user)
        provision_active_signing_key(user)
        db.session.commit()
    except IntegrityError:
        db.session.rollback()
        return jsonify({"error": "User already exists"}), 400

    return jsonify({
        "message": "Account created successfully. You can login now."
    }), 201


@app.route("/api/login", methods=["POST"])
def login():
    if is_rate_limited(
        rate_limit_key("login-ip", client_ip()),
        LOGIN_RATE_LIMIT,
        RATE_LIMIT_WINDOW_SECONDS
    ):
        return rate_limit_response()

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required"}), 400

    username_value = data.get("username")
    password = data.get("password")
    if not isinstance(username_value, str) or not isinstance(password, str):
        return jsonify({"error": "Invalid username or password"}), 401
    username = username_value.strip()

    if not username or not password:
        return jsonify({"error": "Username and password are required"}), 400

    if is_rate_limited(
        rate_limit_key("login-user", identity_hash(username or client_ip())),
        LOGIN_RATE_LIMIT,
        RATE_LIMIT_WINDOW_SECONDS
    ):
        return rate_limit_response()

    user = find_user_by_username(username)

    if not user:
        verify_password(password, DUMMY_PASSWORD_HASH)
        return jsonify({"error": "Invalid username or password"}), 401

    if is_account_locked(user):
        return jsonify({
            "error": "Invalid username or password, or account temporarily unavailable"
        }), 401

    if not verify_password(password, user.password_hash):
        register_failed_login(user)

        return jsonify({
            "error": "Invalid username or password, or account temporarily unavailable"
        }), 401

    reset_login_attempts(user)
    password_upgraded = password_hash_needs_upgrade(user.password_hash)
    if password_upgraded:
        user.password_hash = hash_password(password)

    _, signing_key_rotated = ensure_active_signing_key(user)
    db.session.commit()

    return jsonify({
        "message": "Login successful",
        "token": create_token(user.username_display),
        "username": user.username_display,
        "password_hashing": "PBKDF2-HMAC-SHA512",
        "password_hash_upgraded": password_upgraded,
        "signing_key_rotated": signing_key_rotated,
        "full_scan_required": True
    })


@app.route("/api/logout", methods=["POST"])
def logout():
    token = get_bearer_token()
    _, decoded = decode_token(token)

    if decoded:
        revoke_token(decoded)
        jti = decoded.get("jti")
        with PRESENCE_LOCK:
            socket_ids = [
                socket_id
                for socket_id, socket_session in SOCKET_USERS.items()
                if socket_session.get("jti") == jti
            ]
        for socket_id in socket_ids:
            socketio.server.disconnect(socket_id, namespace="/")

    return jsonify({"message": "Logout complete"})


@app.route("/api/users", methods=["GET"])
def get_users():
    username = require_auth_username()

    if not username:
        return jsonify({"error": "Unauthorized"}), 401

    if is_rate_limited(
        rate_limit_key("users", username),
        API_READ_RATE_LIMIT,
        RATE_LIMIT_WINDOW_SECONDS
    ):
        return rate_limit_response()

    users = User.query.with_entities(
        User.username_display
    ).order_by(User.username_display.asc()).all()

    return jsonify({
        "users": [u.username_display for u in users],
        "profiles": {
            user.username_display: profile_payload(user)
            for user in User.query.order_by(User.username_display.asc()).all()
        }
    })


@app.route("/api/profile", methods=["GET", "PATCH"])
def profile():
    user = require_auth_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "GET":
        return jsonify({"profile": profile_payload(user)})

    data = request.get_json(silent=True)
    if not isinstance(data, dict) or not isinstance(data.get("bio", ""), str):
        return jsonify({"error": "Bio must be text"}), 400
    bio = data.get("bio", "").strip()
    if len(bio) > 160:
        return jsonify({"error": "Bio must be 160 characters or fewer"}), 400
    user.profile_bio = bio
    db.session.commit()
    payload = profile_payload(user)
    emit_to_authenticated_user(user.username_display, "profile_updated", payload)
    socketio.emit("profile_updated", payload)
    return jsonify({"profile": payload})


@app.route("/api/profile/photo", methods=["POST", "DELETE"])
def profile_photo():
    user = require_auth_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if request.method == "DELETE":
        user.profile_image = None
        user.profile_image_mime = None
    else:
        uploaded = request.files.get("photo")
        if not uploaded or uploaded.mimetype not in ALLOWED_PROFILE_IMAGE_TYPES:
            return jsonify({"error": "Choose a JPG, PNG, WEBP, or GIF image"}), 400
        content = uploaded.stream.read(MAX_PROFILE_IMAGE_BYTES + 1)
        if not content or len(content) > MAX_PROFILE_IMAGE_BYTES:
            return jsonify({"error": "Profile image must be 2 MB or smaller"}), 413
        user.profile_image = b64e(content)
        user.profile_image_mime = uploaded.mimetype

    db.session.commit()
    payload = profile_payload(user)
    socketio.emit("profile_updated", payload)
    return jsonify({"profile": payload})


@app.route("/api/account", methods=["DELETE"])
def delete_account():
    user = require_auth_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json(silent=True)
    password = data.get("password") if isinstance(data, dict) else None
    if not isinstance(password, str) or not verify_password(password, user.password_hash):
        return jsonify({"error": "Password is incorrect"}), 403

    message_rows = Message.query.filter(or_(
        Message.sender_hash == user.username_hash,
        Message.receiver_hash == user.username_hash
    )).all()
    message_uuids = [row.message_uuid for row in message_rows]
    if message_uuids:
        Attachment.query.filter(Attachment.message_uuid.in_(message_uuids)).delete(
            synchronize_session=False
        )
    Message.query.filter(or_(
        Message.sender_hash == user.username_hash,
        Message.receiver_hash == user.username_hash
    )).delete(synchronize_session=False)
    SigningKey.query.filter_by(user_hash=user.username_hash).delete(
        synchronize_session=False
    )
    PRIVATE_KEY_STORE.pop(user.username_hash, None)
    username = user.username_display
    db.session.delete(user)
    db.session.commit()
    socketio.emit("account_deleted", {"username": username})
    for socket_id in authenticated_socket_ids(username):
        socketio.server.disconnect(socket_id, namespace="/")
    return jsonify({"message": "Account permanently deleted"})


@app.route("/api/inbox", methods=["GET"])
def inbox():
    user = require_auth_user()

    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if is_rate_limited(
        rate_limit_key("inbox", user.username_hash),
        API_READ_RATE_LIMIT,
        RATE_LIMIT_WINDOW_SECONDS
    ):
        return rate_limit_response()

    rows = Message.query.filter_by(
        receiver_hash=user.username_hash
    ).order_by(Message.created_at.asc()).all()

    messages = []

    for m in rows:
        decrypted, hash_ok, signature_ok, status = decrypt_and_verify_message(m)
        messages.append(
            message_payload(m, "received", decrypted, hash_ok, signature_ok, status)
        )

    return jsonify({"messages": messages})


@app.route("/api/sent", methods=["GET"])
def sent():
    user = require_auth_user()

    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if is_rate_limited(
        rate_limit_key("sent", user.username_hash),
        API_READ_RATE_LIMIT,
        RATE_LIMIT_WINDOW_SECONDS
    ):
        return rate_limit_response()

    rows = Message.query.filter_by(
        sender_hash=user.username_hash
    ).order_by(Message.created_at.asc()).all()

    messages = []

    for m in rows:
        decrypted, hash_ok, signature_ok, status = decrypt_and_verify_message(m)
        messages.append(
            message_payload(m, "sent", decrypted, hash_ok, signature_ok, status)
        )

    return jsonify({"messages": messages})


@app.route("/api/messages", methods=["POST"])
def send_message_api():
    sender_user = require_auth_user()

    if not sender_user:
        return jsonify({"error": "Unauthorized"}), 401

    if is_rate_limited(
        rate_limit_key("message", sender_user.username_hash),
        MESSAGE_RATE_LIMIT,
        RATE_LIMIT_WINDOW_SECONDS
    ):
        return rate_limit_response()

    data = request.get_json(silent=True)
    if not isinstance(data, dict):
        return jsonify({"error": "A JSON object is required"}), 400

    receiver = data.get("receiver")
    plaintext = data.get("message")
    client_id = str(data.get("client_id") or "").strip()

    if client_id and not CLIENT_MESSAGE_ID_RE.fullmatch(client_id):
        return jsonify({"error": "Invalid client message identifier"}), 400

    if not isinstance(receiver, str) or not isinstance(plaintext, str):
        return jsonify({"error": "Receiver and message must be text"}), 400

    result, error = create_verified_message(sender_user, receiver, plaintext)
    if error:
        return jsonify({"error": error}), 400

    receiver_payload = result["receiver_payload"]
    sender_payload = result["sender_payload"]
    receiver_payload["client_id"] = client_id or None
    sender_payload["client_id"] = client_id or None

    delivered_to = emit_to_authenticated_user(
        result["receiver_user"].username_display,
        "receive_message",
        receiver_payload
    )
    sender_payload["delivery_status"] = (
        "delivered" if delivered_to else "stored"
    )
    return jsonify({"message": sender_payload}), 201


@app.route("/api/messages/attachments", methods=["POST"])
def send_attachment_api():
    sender_user = require_auth_user()
    if not sender_user:
        return jsonify({"error": "Unauthorized"}), 401
    if is_rate_limited(
        rate_limit_key("message", sender_user.username_hash),
        MESSAGE_RATE_LIMIT,
        RATE_LIMIT_WINDOW_SECONDS
    ):
        return rate_limit_response()

    receiver = (request.form.get("receiver") or "").strip()
    caption = (request.form.get("message") or "").strip()
    client_id = (request.form.get("client_id") or "").strip()
    uploaded = request.files.get("file")
    if client_id and not CLIENT_MESSAGE_ID_RE.fullmatch(client_id):
        return jsonify({"error": "Invalid client message identifier"}), 400
    if not uploaded:
        return jsonify({"error": "Choose a file to share"}), 400

    mime_type = (uploaded.mimetype or "application/octet-stream").lower()
    allowed = mime_type in ALLOWED_ATTACHMENT_TYPES or any(
        mime_type.startswith(prefix) for prefix in ALLOWED_ATTACHMENT_PREFIXES
    )
    if not allowed:
        return jsonify({"error": "This file type is not allowed"}), 400
    content = uploaded.stream.read(MAX_ATTACHMENT_BYTES + 1)
    if not content or len(content) > MAX_ATTACHMENT_BYTES:
        return jsonify({"error": "File must be 15 MB or smaller"}), 413

    result, error = create_verified_message(
        sender_user,
        receiver,
        caption,
        attachment_content=content,
        attachment_filename=uploaded.filename or "attachment",
        attachment_mime=mime_type
    )
    if error:
        return jsonify({"error": error}), 400

    receiver_payload = result["receiver_payload"]
    sender_payload = result["sender_payload"]
    receiver_payload["client_id"] = client_id or None
    sender_payload["client_id"] = client_id or None
    delivered_to = emit_to_authenticated_user(
        result["receiver_user"].username_display,
        "receive_message",
        receiver_payload
    )
    sender_payload["delivery_status"] = (
        "delivered" if delivered_to else "stored"
    )
    return jsonify({"message": sender_payload}), 201


@app.route("/api/attachments/<message_uuid>", methods=["GET"])
def download_attachment(message_uuid):
    user = require_auth_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401
    message_row = Message.query.filter_by(message_uuid=message_uuid).first()
    if not message_row or message_row.deleted_at:
        return jsonify({"error": "Attachment not found"}), 404
    if user.username_hash not in {message_row.sender_hash, message_row.receiver_hash}:
        return jsonify({"error": "Forbidden"}), 403
    attachment = Attachment.query.filter_by(message_uuid=message_uuid).first()
    if not attachment:
        return jsonify({"error": "Attachment not found"}), 404
    try:
        content = decrypt_and_verify_attachment(message_row, attachment)
    except Exception:
        app.logger.exception("Attachment verification failed")
        return jsonify({"error": "Attachment failed integrity verification"}), 409
    return send_file(
        io.BytesIO(content),
        mimetype=attachment.mime_type,
        as_attachment=False,
        download_name=attachment.filename,
        max_age=0
    )


@app.route("/api/messages/<message_uuid>", methods=["DELETE"])
def unsend_message(message_uuid):
    sender_user = require_auth_user()
    if not sender_user:
        return jsonify({"error": "Unauthorized"}), 401
    message_row = Message.query.filter_by(message_uuid=message_uuid).first()
    if not message_row:
        return jsonify({"error": "Message not found"}), 404
    if message_row.sender_hash != sender_user.username_hash:
        return jsonify({"error": "Only the sender can unsend this message"}), 403
    if not message_row.deleted_at:
        message_row.deleted_at = utc_now()
        db.session.commit()

    receiver = User.query.filter_by(username_hash=message_row.receiver_hash).first()
    sender_payload = message_payload(
        message_row, "sent", "", True, True, "Message unsent"
    )
    receiver_payload = message_payload(
        message_row, "received", "", True, True, "Message unsent"
    )
    emit_to_authenticated_user(sender_user.username_display, "message_unsent", sender_payload)
    if receiver:
        emit_to_authenticated_user(receiver.username_display, "message_unsent", receiver_payload)
    return jsonify({"message": sender_payload})


@app.route("/api/sync", methods=["GET"])
def sync_session():
    user = require_auth_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    if is_rate_limited(
        rate_limit_key("sync", user.username_hash),
        API_READ_RATE_LIMIT,
        RATE_LIMIT_WINDOW_SECONDS
    ):
        return rate_limit_response()

    _, signing_key_rotated = ensure_active_signing_key(user)
    if signing_key_rotated:
        db.session.commit()

    messages, scan = scan_messages_for_user(user)
    users = User.query.with_entities(
        User.username_display
    ).filter(
        User.username_hash != user.username_hash
    ).order_by(User.username_display.asc()).all()

    profile_rows = User.query.order_by(User.username_display.asc()).all()
    return jsonify({
        "authenticated_as": user.username_display,
        "users": [row.username_display for row in users],
        "profiles": {
            row.username_display: profile_payload(row) for row in profile_rows
        },
        "profile": profile_payload(user),
        "messages": messages,
        "scan": scan,
        "signing_key_ready": True,
        "signing_key_rotated": signing_key_rotated,
        "security": security_status_payload(user)
    })


@app.route("/api/security-status", methods=["GET"])
def security_status():
    user = require_auth_user()

    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify(security_status_payload(user))


# ==========================================================
# Debug / Database Proof APIs
# ==========================================================

@app.route("/api/debug/users", methods=["GET"])
def debug_users():
    if not DEMO_DB_VIEW_ENABLED:
        return jsonify({"error": "Database proof view is disabled"}), 403

    user = require_auth_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    return jsonify({
        "note": "Plaintext and reusable password hashes are never exposed by this API.",
        "users": [{
            "id": user.id,
            "username_display": user.username_display,
            "password_hash_algorithm": password_hash_label(user.password_hash),
            "password_hash_stored": bool(user.password_hash),
            "password_hash_value": "Redacted",
            "failed_attempts": user.failed_attempts,
            "rsa_public_key_fingerprint": hashlib.sha256(
                user.rsa_public_key.encode("utf-8")
            ).hexdigest()[:16],
            "private_key_storage_status": "AES-256-GCM wrapped; plaintext not stored"
        }]
    })


@app.route("/api/debug/messages", methods=["GET"])
def debug_messages():
    if not DEMO_DB_VIEW_ENABLED:
        return jsonify({"error": "Database proof view is disabled"}), 403

    user = require_auth_user()
    if not user:
        return jsonify({"error": "Unauthorized"}), 401

    rows = Message.query.filter(or_(
        Message.sender_hash == user.username_hash,
        Message.receiver_hash == user.username_hash
    )).order_by(Message.id.asc()).all()

    return jsonify({
        "note": "Plaintext message is not stored in the database.",
        "messages": [
            {
                "id": m.id,
                "message_uuid": m.message_uuid,
                "sender_display": m.sender_display,
                "receiver_display": m.receiver_display,
                "ciphertext_bytes": len(b64d(m.encrypted_message)),
                "aes_gcm_tag_present": bool(m.aes_tag),
                "sha512_hash_stored": bool(m.plaintext_sha512_hash),
                "sha512_hash_value": "Redacted",
                "digital_signature_present": bool(m.digital_signature),
                "security_version": m.security_version or 1,
                "created_at": m.created_at.strftime("%Y-%m-%d %H:%M:%S")
            }
            for m in rows
        ]
    })


# ==========================================================
# Socket.IO Events
# ==========================================================


def unregister_socket(socket_id: str):
    with PRESENCE_LOCK:
        socket_session = SOCKET_USERS.pop(socket_id, None)
        if not socket_session:
            return None, False

        username = socket_session["username"]
        ONLINE_USER_COUNTS[username] = max(
            0,
            ONLINE_USER_COUNTS[username] - 1
        )
        became_offline = ONLINE_USER_COUNTS[username] == 0
        if became_offline:
            ONLINE_USER_COUNTS.pop(username, None)
        return username, became_offline


def broadcast_presence(username: str, online: bool):
    socketio.emit("presence_update", {
        "username": username,
        "online": online
    })


def authenticated_socket_ids(username: str):
    now_timestamp = time.time()
    expired_socket_ids = []
    valid_socket_ids = []

    with PRESENCE_LOCK:
        socket_sessions = list(SOCKET_USERS.items())

    for socket_id, socket_session in socket_sessions:
        if socket_session.get("username") != username:
            continue
        if (
            socket_session.get("expires_at", 0) <= now_timestamp
            or socket_session.get("jti") in TOKEN_BLOCKLIST
        ):
            expired_socket_ids.append(socket_id)
        else:
            valid_socket_ids.append(socket_id)

    for socket_id in expired_socket_ids:
        socketio.server.disconnect(socket_id, namespace="/")
    return valid_socket_ids


def emit_to_authenticated_user(username: str, event_name: str, payload: dict):
    socket_ids = authenticated_socket_ids(username)
    for socket_id in socket_ids:
        socketio.emit(event_name, payload, to=socket_id)
    return len(socket_ids)


@socketio.on("join")
def socket_join(data):
    data = data if isinstance(data, dict) else {}
    user, decoded = decode_token(data.get("token"))

    if not user:
        emit("auth_error", {"error": "Invalid token"})
        return

    old_username, became_offline = unregister_socket(request.sid)
    if old_username and became_offline:
        broadcast_presence(old_username, False)

    with PRESENCE_LOCK:
        SOCKET_USERS[request.sid] = {
            "username": user.username_display,
            "username_hash": user.username_hash,
            "jti": decoded["jti"],
            "expires_at": float(decoded["exp"])
        }
        ONLINE_USER_COUNTS[user.username_display] += 1
        online_users = sorted(ONLINE_USER_COUNTS.keys(), key=str.lower)

    join_room(user.username_display)
    broadcast_presence(user.username_display, True)

    emit("joined", {
        "message": f"{user.username_display} joined secure room",
        "online_users": online_users
    })


def forward_call_signal(event_name: str, data: dict, payload_keys: tuple):
    data = data if isinstance(data, dict) else {}
    with PRESENCE_LOCK:
        socket_session = SOCKET_USERS.get(request.sid)
    if not socket_session or (
        socket_session.get("expires_at", 0) <= time.time()
        or socket_session.get("jti") in TOKEN_BLOCKLIST
    ):
        emit("auth_error", {"error": "Join the secure session first"})
        socketio.server.disconnect(request.sid, namespace="/")
        return

    target = str(data.get("target") or "").strip()
    target_user = find_user_by_username(target) if is_valid_username(target) else None
    if not target_user or target_user.username_hash == socket_session["username_hash"]:
        emit("call_error", {"error": "Call recipient is invalid"})
        return
    payload = {
        "from": socket_session["username"],
        "target": target_user.username_display,
        "call_id": str(data.get("call_id") or "")[:80]
    }
    for key in payload_keys:
        payload[key] = data.get(key)
    delivered = emit_to_authenticated_user(
        target_user.username_display,
        event_name,
        payload
    )
    if not delivered:
        emit("call_error", {
            "call_id": payload["call_id"],
            "error": f"{target_user.username_display} is offline"
        })


@socketio.on("call_offer")
def socket_call_offer(data):
    forward_call_signal("incoming_call", data, ("description", "mode"))


@socketio.on("call_answer")
def socket_call_answer(data):
    forward_call_signal("call_answer", data, ("description", "accepted", "mode"))


@socketio.on("ice_candidate")
def socket_ice_candidate(data):
    forward_call_signal("ice_candidate", data, ("candidate",))


@socketio.on("call_end")
def socket_call_end(data):
    forward_call_signal("call_ended", data, ())


@socketio.on("disconnect")
def socket_disconnect():
    username, became_offline = unregister_socket(request.sid)
    if username and became_offline:
        broadcast_presence(username, False)


@socketio.on("send_message")
def socket_send_message(data):
    data = data if isinstance(data, dict) else {}
    client_id = str(data.get("client_id") or "").strip()

    def send_error(message):
        emit("send_error", {"error": message, "client_id": client_id or None})

    if client_id and not CLIENT_MESSAGE_ID_RE.fullmatch(client_id):
        send_error("Invalid client message identifier")
        return

    sender_user, decoded = decode_token(data.get("token"))

    if not sender_user:
        send_error("Invalid token")
        return

    with PRESENCE_LOCK:
        socket_session = SOCKET_USERS.get(request.sid)
    if (
        not socket_session
        or socket_session.get("jti") != decoded.get("jti")
        or socket_session.get("username_hash") != sender_user.username_hash
    ):
        send_error("Realtime session is not authenticated")
        return

    if is_rate_limited(
        rate_limit_key("message", sender_user.username_hash),
        MESSAGE_RATE_LIMIT,
        RATE_LIMIT_WINDOW_SECONDS
    ):
        send_error("Too many messages. Please wait and try again.")
        return

    receiver = (data.get("receiver") or "").strip()
    plaintext = data.get("message")

    if not isinstance(plaintext, str):
        send_error("Message must be text")
        return

    result, error = create_verified_message(sender_user, receiver, plaintext)
    if error:
        send_error(error)
        return

    receiver_payload = result["receiver_payload"]
    sender_payload = result["sender_payload"]
    receiver_payload["client_id"] = client_id or None
    sender_payload["client_id"] = client_id or None

    delivered_to = emit_to_authenticated_user(
        result["receiver_user"].username_display,
        "receive_message",
        receiver_payload
    )
    sender_payload["delivery_status"] = (
        "delivered" if delivered_to else "stored"
    )
    emit("sent_message", sender_payload)


if __name__ == "__main__":
    print(f"Badri 313 running at: http://{HOST}:{PORT}")
    print(f"Database demo page: http://{HOST}:{PORT}/debug-db")
    socketio.run(app, host=HOST, port=PORT, debug=FLASK_DEBUG)
