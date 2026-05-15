# Secure Real-Time Messaging System

A complete cryptography subject project built with Python, Flask, Socket.IO, SQLite, AES-256-GCM, SHA-512, RSA digital signature, JWT, and bcrypt.

## Project Title

Secure Real-Time Messaging System Using AES-256-GCM, SHA-512 Hashing, and RSA Digital Signature

## Main Features

- User registration and login
- Password hashing using bcrypt
- JWT authentication after successful login
- Sender and receiver-based messaging
- Real-time communication using Socket.IO
- AES-256-GCM message encryption
- SHA-512 hash generation and verification
- RSA digital signature generation and verification
- Encrypted message storage in SQLite database
- Separate Send, Receive/Inbox, and Sent message sections
- Database Security View for demonstration
- Login attempt tracking
- Message UUID for replay-protection demonstration

## Folder Structure

```text
secure_messaging_v3_final/
├── app.py
├── requirements.txt
├── README.md
└── templates/
    ├── index.html
    └── debug_db.html
```

## How to Run in VS Code

Open this folder in VS Code.

```bash
pip install -r requirements.txt
python app.py
```

Then open:

```text
http://127.0.0.1:5000
```

Database security view:

```text
http://127.0.0.1:5000/debug-db
```

## Testing with Multiple Users

Use different browser sessions:

```text
Chrome normal tab      = UserA
Chrome incognito tab   = UserB
Edge or Firefox        = UserC
```

## Database Location

After running the app, SQLite database is created here:

```text
instance/secure_chat.db
```

To view it inside VS Code, install the SQLite Viewer extension and open the database file.

## Security Workflow

```text
User Registration
↓
Password hashed using bcrypt
↓
User Login
↓
JWT token generated
↓
Sender writes message
↓
Backend encrypts message using AES-256-GCM
↓
Backend generates SHA-512 hash
↓
Backend signs message using sender RSA private key
↓
Encrypted message + nonce + AES tag + hash + signature stored in SQLite
↓
Socket.IO sends payload to receiver
↓
Receiver side/backend decrypts message
↓
SHA-512 hash verifies integrity
↓
RSA public key verifies sender authenticity
↓
Receiver sees verified plaintext message
```

## Academic Note

For classroom demonstration, the RSA private key is stored in the database so the system can sign messages automatically. In a production-grade system, private keys should be stored securely on the client side or inside a secure key manager, not directly in the database.

## Windows / Python 3.13 Fix

This project uses Flask-SocketIO with `async_mode="threading"` so it works on Windows and newer Python versions without Eventlet compatibility errors.

Run:

```bash
pip install -r requirements.txt
python app.py
```
