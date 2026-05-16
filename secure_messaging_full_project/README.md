# Secure Real-Time Messaging System

This is a Flask + Socket.IO academic secure messaging project.

## Features

- Username + valid email + password registration
- Login using username or email
- bcrypt password hashing
- JWT authentication
- Real-time messaging with Socket.IO
- AES-256-GCM encrypted message storage
- SHA-512 message hash verification
- RSA digital signature verification
- UUID for each message
- Database security proof page

## Folder Structure

```text
secure_messaging_full_project/
│
├── app.py
├── .env
├── requirements.txt
├── README.md
│
└── templates/
    ├── index.html
    └── debug.html
```

## Run Steps

### 1. Open terminal in project folder

```bash
cd secure_messaging_full_project
```

### 2. Install packages

```bash
pip install -r requirements.txt
```

### 3. Run app

```bash
python app.py
```

### 4. Open browser

```text
http://127.0.0.1:5000
```

### 5. Test real-time message

Open two browser windows:

```text
Window 1: Register/Login user A
Window 2: Register/Login user B
```

Then send message from user A to user B.

## Database Debug Page

```text
http://127.0.0.1:5000/debug-db
```

This page shows:
- Password stored as bcrypt hash
- Message stored as ciphertext
- Nonce
- AES tag
- SHA-512 hash
- RSA signature start
- UUID
- Public key only
- Private key not stored in database

## Important Academic Limitation

This project is secure-storage based, not full end-to-end encryption.

The server can decrypt messages because AES encryption/decryption happens on the backend. For a real WhatsApp-like E2EE system, encryption should happen on the client side using each user's public key/session key.

RSA private keys are kept in server memory only for the academic demonstration. If the server restarts, existing users cannot sign new messages unless they re-register or you implement encrypted private-key storage.