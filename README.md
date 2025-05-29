# 🔐 Secure Communication Project: RSA, Digital Signatures, and AES

## 👥 Authors
- **Omar** – `Student_A.py`
- **Mahmoud** – `Student_B.py`

---

## 📘 Overview

This project implements a secure communication protocol between two students using a combination of cryptographic techniques:

- **RSA** for key exchange and digital signatures  
- **AES** for symmetric message encryption  
- **SHA-256** for hashing and integrity  

The communication sequence includes:
- Key exchange
- Session key creation
- Message encryption and decryption
- Digital signature generation and verification

---

## 🔐 RSA Key Generation Process

### ✔️ Key Generation
- Each student generates a **2048-bit RSA key pair** using `Crypto.PublicKey.RSA`: 
```python
self.rsa_key = RSA.generate(2048)
```
### 💾 Export and Save
- Student A saves the keys to .pem files.
- Student B keeps the keys in memory.

### 🔁 Exchange
- Public keys are exchanged over the socket connection.
- Enables asymmetric encryption and digital signature verification.

---

## 🔁 Asymmetric Encryption / Decryption (RSA)

### 🔒 Encryption
Use the peer's public key to encrypt:
```python
cipher = PKCS1_OAEP.new(self.peer_public_key)
encrypted_data = cipher.encrypt(my_random)
```

### 🔓 Decryption
Use your own private key to decrypt:
```python
cipher = PKCS1_OAEP.new(self.rsa_key)
decrypted_data = cipher.decrypt(peer_encrypted)
```

---

## ✍️ Digital Signatures

### 🧾 Signature Generation
- Hash the message with SHA-256.
- Sign the hash using the sender’s private RSA key:

```python
h = SHA256.new(message.encode())
signature = pkcs1_15.new(self.rsa_key).sign(h)
```

### ✅ Signature Verification
- Hash the decrypted message.
- Verify the signature using the sender’s public RSA key:
```python
pkcs1_15.new(self.peer_public_key).verify(h, signature)
```

Confirms:

- Sender authenticity
- Message integrity

---

## 🔐 Symmetric Encryption (AES)
### 🗝️ Session Key Establishment
- Each peer generates a 128-bit random value:

```python
get_random_bytes(16)
```
- Values are exchanged encrypted with RSA.
- The session key is derived by hashing the concatenated values:

```python
combined = my_random + peer_random
self.session_key = hashlib.sha256(combined).digest()[:16]
```
### 🔏 Message Encryption
```python
cipher = AES.new(self.session_key, AES.MODE_EAX)
ciphertext, tag = cipher.encrypt_and_digest(message.encode())
```
### 🔓 Message Decryption
```python
cipher = AES.new(self.session_key, AES.MODE_EAX, nonce=nonce)
plaintext = cipher.decrypt_and_verify(ciphertext, tag)
```
**Ensures confidentiality and integrity of the messages.**

---

## 🔄 Communication Flow Summary
1. Key Exchange: Exchange RSA public keys.
2. Session Key Creation: Exchange and combine random values securely.
3. Message Transmission:
    - Encrypt with AES
    - Sign with RSA
    - Serialize and send

4. Message Reception:
    - Decrypt with AES
    - Verify with RSA

---

## 🛡️ Security Highlights
- Confidentiality: AES encryption
- Authentication & Integrity: RSA digital signatures
- Forward Secrecy: New session key per session using fresh randomness

---

## ⚙️ Requirements
- python 3.x
- pycryptodome

Install Dependencies
```python
pip install pycryptodome
```
---

## ▶️ How to Run
Open two terminals:

1. Start Student A (initiator):
```python
python Student_A.py
```

2. Then start Student B:
```python
python Student_B.py
```
---

## 📝 Notes
- Communication is local (localhost).
- Ensure chosen ports are open and not blocked by firewalls.
