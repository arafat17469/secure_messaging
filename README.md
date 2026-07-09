# Badri 313

![Python](https://img.shields.io/badge/Python-3.10%2B-blue)
![Flask](https://img.shields.io/badge/Flask-3.0-black)
![Socket.IO](https://img.shields.io/badge/Socket.IO-Realtime-00a884)
![SQLite](https://img.shields.io/badge/SQLite-Database-4479a1)
![Security](https://img.shields.io/badge/Security-AES--GCM%20%7C%20RSA--PSS%20%7C%20bcrypt-green)

Badri 313 is a secure real-time messaging web application built with Flask, Flask-SocketIO, SQLite, AES-256-GCM encryption, SHA-512 integrity checks, RSA-PSS signatures, JWT authentication, and bcrypt password hashing.

&copy; 2026 Arafat Rahman. All rights reserved.

## Highlights

- Real-time private messaging with Socket.IO rooms
- WhatsApp-inspired responsive chat interface
- User registration and login with bcrypt password hashing
- Strong password policy with confirmation and show-password controls
- JWT authentication with issuer, audience, expiry, `jti`, and logout revocation
- AES-256-GCM encrypted message storage
- SHA-512 plaintext integrity proof
- RSA-PSS digital signature verification
- Login lockout and in-memory rate limiting
- Security headers, request-size limits, and CORS controls
- Protected database proof page for academic demonstration
- Auto backend health detection for local development

## Tech Stack

| Layer | Technology |
| --- | --- |
| Backend | Python, Flask, Flask-SocketIO |
| Database | SQLite with Flask-SQLAlchemy |
| Frontend | HTML, CSS, vanilla JavaScript |
| Authentication | JWT, bcrypt |
| Encryption | AES-256-GCM |
| Integrity | SHA-512 |
| Signature | RSA-PSS with SHA-512 |
| Realtime | Socket.IO |

## Project Structure

```text
secure_messaging/
|-- app.py
|-- requirements.txt
|-- README.md
|-- .env.example
|-- .gitignore
|-- templates/
|   |-- index.html
|   `-- debug_db.html
`-- instance/
    |-- secure_chat.db        # local runtime database, ignored for GitHub
    `-- secret.key            # local generated dev secret, ignored for GitHub
```

## Quick Start

Clone the repository:

```bash
git clone https://github.com/arafat17469/secure_messaging.git
cd secure_messaging
```

Create and activate a virtual environment:

```bash
python -m venv .venv
```

Windows PowerShell:

```powershell
.\.venv\Scripts\Activate.ps1
```

macOS/Linux:

```bash
source .venv/bin/activate
```

Install dependencies:

```bash
pip install -r requirements.txt
```

Copy the environment template:

```bash
copy .env.example .env
```

On macOS/Linux:

```bash
cp .env.example .env
```

Run the application:

```bash
python app.py
```

Open the app:

```text
http://127.0.0.1:5000
```

## Environment Variables

The app can start in local development even if `.env` is missing. In that case, it creates a local development key at `instance/secret.key`. For a cleaner setup, create `.env` from `.env.example`.

```env
SECRET_KEY=replace-this-with-a-long-random-secret
DATABASE_URL=sqlite:///secure_chat.db
MAX_LOGIN_ATTEMPTS=5
LOCK_MINUTES=5
JWT_EXPIRE_HOURS=6
JWT_ISSUER=secure-messaging
JWT_AUDIENCE=secure-messaging-users
BCRYPT_ROUNDS=12
MIN_PASSWORD_LENGTH=8
PASSWORD_REQUIRE_COMPLEXITY=True
MAX_MESSAGE_CHARS=2000
MAX_JSON_BYTES=16384
RATE_LIMIT_WINDOW_SECONDS=60
REGISTER_RATE_LIMIT=8
LOGIN_RATE_LIMIT=12
MESSAGE_RATE_LIMIT=40
API_READ_RATE_LIMIT=120
DEMO_DB_VIEW_ENABLED=True
CORS_ALLOWED_ORIGINS=http://127.0.0.1:5000,http://localhost:5000,http://127.0.0.1:5001,http://localhost:5001,http://127.0.0.1:5500,http://localhost:5500,null
HOST=127.0.0.1
PORT=5000
FLASK_DEBUG=False
```

## How To Test Realtime Messaging

Use two different browser sessions:

```text
Session 1: Chrome normal window      -> User A
Session 2: Chrome incognito window   -> User B
Session 3: Edge/Firefox              -> User C
```

Register two users, login from both sessions, select the other user from the sidebar, and send a message. Messages are delivered live through Socket.IO.

Example password that satisfies the default policy:

```text
Secret1!
```

## Database Security View

After logging in, open:

```text
http://127.0.0.1:5000/debug-db
```

The proof page shows that:

- plaintext passwords are not stored
- bcrypt password hashes are stored
- plaintext messages are not stored
- ciphertext, nonce, AES tag, SHA-512 hash, signature, and UUID are stored
- RSA private keys are not stored in the database

Set this to disable the proof page APIs:

```env
DEMO_DB_VIEW_ENABLED=False
```

## Security Workflow

```text
Registration
  -> Validate username and password policy
  -> Hash password with bcrypt
  -> Generate RSA key pair
  -> Store public key in SQLite
  -> Keep private key in server memory for demo signing

Login
  -> Verify bcrypt hash
  -> Reset failed login attempts
  -> Issue JWT with issuer, audience, expiry, subject, and JTI

Message Send
  -> Authenticate Socket.IO event with JWT
  -> Rate-limit sender
  -> Encrypt plaintext with AES-256-GCM
  -> Create SHA-512 integrity hash
  -> Sign plaintext with RSA-PSS
  -> Save encrypted record in SQLite
  -> Emit verified payload to receiver room in real time

Message Read
  -> Decrypt with AES-GCM tag verification
  -> Compare SHA-512 hash
  -> Verify RSA-PSS signature with sender public key
  -> Return verified message payload
```

## API Overview

| Method | Endpoint | Description |
| --- | --- | --- |
| `GET` | `/api/health` | Backend health check |
| `POST` | `/api/register` | Create a new user |
| `POST` | `/api/login` | Login and receive JWT |
| `POST` | `/api/logout` | Revoke current JWT in memory |
| `GET` | `/api/users` | List registered users |
| `GET` | `/api/inbox` | Load received messages |
| `GET` | `/api/sent` | Load sent messages |
| `GET` | `/api/security-status` | Show active security settings |
| `GET` | `/api/debug/users` | Database proof for users |
| `GET` | `/api/debug/messages` | Database proof for messages |

Socket.IO events:

| Event | Direction | Description |
| --- | --- | --- |
| `join` | Client to server | Join authenticated user room |
| `send_message` | Client to server | Send encrypted realtime message |
| `receive_message` | Server to receiver | Deliver received message |
| `sent_message` | Server to sender | Confirm sent message |
| `send_error` | Server to client | Report sending error |
| `auth_error` | Server to client | Report invalid authentication |

## Troubleshooting

### Registration says backend is not running

Start Flask from the project folder:

```bash
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

### API route not found

You are likely opening the page with VS Code Live Server or as a local file while Flask is not running. The frontend can detect a local backend, but the Flask server must still be running.

### Password is rejected

The default policy requires:

- at least 8 characters
- one uppercase letter
- one lowercase letter
- one number
- one symbol
- password and confirm password must match exactly

### Existing users cannot send after server restart

For classroom/demo simplicity, RSA private keys are kept in server memory only. Existing users can login after restart, but they cannot sign new messages unless they create a fresh account or encrypted private-key storage is implemented.

## Academic Security Note

Badri 313 demonstrates secure encrypted storage, integrity checking, authenticated realtime delivery, and digital signatures. It is not full end-to-end encryption because the backend receives plaintext before encryption.

For production-grade E2EE, encryption should happen on the client before the server receives message content, private keys should be stored client-side or in a secure key manager, and session-key exchange should be implemented.

## License

All rights reserved by Arafat Rahman.
