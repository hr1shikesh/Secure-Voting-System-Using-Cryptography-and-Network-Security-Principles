Sure! Here’s the updated version of your README where the `plaintext` effect has been removed after the "Project Structure" section:

---

# 🗳️ Secure E-Voting System

This is a secure and privacy-preserving e-voting platform implemented in Python. The system supports end-to-end encryption, digital signatures, HMAC verification, and SSL-secured communication between a client and server.

---

## 🔐 Features

- ✅ Voter registration with password hashing (PBKDF2)
- ✅ Voter authentication with secure salted hash verification
- ✅ Encrypted vote submission (AES-GCM)
- ✅ Vote integrity and authenticity via HMAC and digital signatures
- ✅ Ephemeral key exchange (hybrid encryption model)
- ✅ Secure TLS (SSL) communication between client and server
- ✅ Candidate listing and result tallying
- ✅ Thread-safe multi-client server with SQLite backend

---

## 🧠 Technologies Used

- Python 3
- `sqlite3` – Database
- `ssl`, `socket`, `threading` – Secure networking
- `pycryptodome` – Cryptographic operations (AES, RSA, HMAC, PBKDF2)
- Custom `CryptoManager` class for all crypto operations

---

## 📁 Project Structure

```
.
├── client.py              # Client-side script with CLI menu
├── server.py              # Server-side script with all endpoints
├── crypto_utils.py        # Handles all encryption, hashing, signing
├── candidates.json        # List of candidates for each position
├── certs/
│   ├── server.crt         # Server certificate
│   └── server.key         # Server private key
├── voters.db              # SQLite DB for voters and votes
└── README.md
```

---

## 🧪 Setup Instructions

### 🔧 Requirements

- Python 3.7+

### Install dependencies:

```bash
pip install pycryptodome
```

### 🔐 Generate SSL Certificates

If you don't already have `server.crt` and `server.key`, generate a self-signed certificate:

```bash
mkdir certs
openssl req -new -x509 -days 365 -nodes -out certs/server.crt -keyout certs/server.key
```

### ⚙️ Running the Server

```bash
python server.py
```

The server starts on localhost:5000 with SSL.

### 🧑‍💻 Running the Client

```bash
python client.py
```

Client menu options:

- Register as a new voter
- Login using Aadhaar and password
- View available candidates
- Cast a vote
- View election results

---

## 🔏 Security Overview

| Mechanism            | Description                                                  |
|----------------------|--------------------------------------------------------------|
| Password Hashing     | PBKDF2 with salt and 1,000,000 iterations                    |
| Vote Encryption      | AES-GCM (128/256-bit), key derived via ephemeral key exchange|
| Integrity Check      | HMAC (SHA-256) of ciphertext using PBKDF2-derived key        |
| Authenticity         | Digital signature using voter's private key                  |
| Transport Security   | TLS with X.509 certs                                         |

Votes are end-to-end encrypted, tamper-evident, and authentic. No plaintext votes are stored or transmitted.

---

## 📊 Tallying Results

The server aggregates votes per candidate per position and ensures each voter can only vote once per position.

Sample response:

```json
{
  "President": {
    "Alice": 3,
    "Bob": 2
  },
  "Treasurer": {
    "Carol": 4,
    "Dave": 1
  }
}
```

---

## 📎 Notes

- Aadhaar is used as a unique voter ID (could be replaced with student ID, email, etc.)
- All communication is secured with TLS
- Private keys are only stored locally on the client

---

## 🛡️ Legal / Ethics

This system is intended for educational, academic, and small-scale organizational purposes. Do not use for government or large-scale elections without thorough auditing and enhancements.

---

## 📣 Credits

Developed by [Your Name].  
Crypto implementation powered by PyCryptodome.

---

## 📌 Future Improvements

- ✅ Admin dashboard for election management
- ✅ QR-code login
- ✅ Blockchain backend for auditability
- ✅ Vote receipt/token for voter verification
- ✅ Encrypted vote backup/recovery

---
