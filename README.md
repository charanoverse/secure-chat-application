# 🔐 Secure Chat App  
**End-to-End Encrypted, Searchable, and Privacy-Focused Messaging System**

---

## 🚀 Overview

**Secure Chat App** is a command-line based encrypted chat application built with Python that emphasizes **confidentiality**, **integrity**, and **forward secrecy**.  
It implements modern cryptographic techniques (AES-GCM, X25519, HKDF) and privacy-enhancing features like **TTL messages**, **searchable encrypted history**, and **relay-based communication** — ensuring secure and private messaging across networks.

---

## 🧩 Key Features

- ✅ **End-to-End Encryption (AES-GCM)** — ensures message confidentiality and integrity  
- 🔐 **Ephemeral X25519 Handshake** — for perfect forward secrecy  
- 🕚 **TTL Messages** — messages self-destruct after a chosen time  
- 🔍 **Searchable Encrypted History** — search messages without exposing plaintext  
- 🌐 **Relay Mode** — enables secure communication over the internet via WebSocket relay  
- 🧱 **Message Framing** — reliable transmission of encrypted packets  
- 🧰 **Typer CLI Interface** — intuitive command-line usage  
- 💾 **SQLite Encrypted Storage** — secure, local message database  

---

## 🛠️ Installation

### 1. Clone the Repository
```bash
git clone https://github.com/<your-username>/secure-chat-app.git
cd secure-chat-app
```

### 2. Set Up Virtual Environment
```bash
python -m venv .venv
```

Activate it:
- **Windows**
  ```bash
  .venv\Scripts\activate
  ```
- **Linux/macOS**
  ```bash
  source .venv/bin/activate
  ```

### 3. Install Dependencies
```bash
pip install -r requirements.txt
```

---

## 🧱 Building the Package

To build distributable `.whl` and `.tar.gz` files:

```bash
pip install build
python -m build
```

This will create your package in the `dist/` directory.

---

## ⚙️ Usage

### 🖥️ Starting the Server
```bash
python -m secure_chat.cli server --peer-id SERVER --priv server_priv.pem --bind 0.0.0.0 --port 65432 --history secure_chat_history.db
```

### 💬 Starting the Client
```bash
python -m secure_chat.cli client --host 127.0.0.1 --port 65432 --peer-id ALICE --server-peer-id SERVER --server-pub server_pub.pem --history secure_chat_history.db
```

---

## 🔎 Searching Encrypted Messages

Search for any word or phrase securely without decrypting your message history:

```bash
python -m secure_chat.cli search "message"
```

---

## ⏳ Sending TTL (Self-Destructing) Messages

Messages automatically delete after the given number of seconds:

```
/ttl 3 write a message
```
*(This sends a message that disappears 3 seconds after delivery.)*

---

## 🌐 Relay Mode (Internet Mode)

Use this when clients and servers are on different networks.

### Start the Relay Server
```bash
python -m secure_chat.relay.relay_server
```

### Connect via Relay
```bash
python -m secure_chat.cli client --host 127.0.0.1 --port 65432 --peer-id ALICE --server-peer-id SERVER --server-pub server_pub.pem --history secure_chat_history.db --relay ws://localhost:8000/ws/room1
```

The relay only forwards encrypted frames and never sees message plaintext.

---

## 🧹 Clearing Cache (Optional)

If you face import or bytecode issues:

```powershell
Get-ChildItem -Path . -Include "__pycache__" -Recurse | Remove-Item -Recurse -Force -ErrorAction SilentlyContinue
Get-ChildItem -Path . -Include "*.pyc" -Recurse | Remove-Item -Force -ErrorAction SilentlyContinue
```

---

## 🧪 Project Phases Implemented

### **Phase 0 — Baseline Hardening**
- Refactored to package (no globals; dependency injection for keys/state)  
- Replaced AES-CBC with AES-GCM for authenticated encryption  
- Added message framing (length-prefix)  
- Introduced Typer CLI commands  

### **Phase 1 — Protocol v1 (Security & Integrity)**
- Ephemeral X25519 handshake for key exchange  
- HKDF-based session keys and rekeying for forward secrecy  
- Replay protection with sequence and timestamp AAD  
- Server public key pinning to prevent MITM  

### **Phase 2 — Searchable Encrypted History**
- Tokenized message indexing using HMAC(K_idx)  
- Encrypted SQLite message storage  
- Secure search feature via CLI  

### **Phase 3 — Ephemeral & Privacy Features**
- TTL-based message expiry and secure delete  
- Anonymous peer IDs (Base58) and QR invite support  

### **Phase 4 — Relay (Internet Mode)**
- FastAPI WebSocket relay for encrypted message routing  
- Room-based communication with optional access tokens  
- Automatic client fallback (direct TCP → relay)  
- Basic moderation and rate limiting  

---

## 🖖️ Example Workflow

1. **Start Server**
   ```bash
   python -m secure_chat.cli server --peer-id SERVER --priv server_priv.pem --bind 0.0.0.0
   ```

2. **Connect Client**
   ```bash
   python -m secure_chat.cli client --host 127.0.0.1 --port 65432 --peer-id ALICE --server-peer-id SERVER --server-pub server_pub.pem
   ```

3. **Chat Securely**  
   Send messages, use `/ttl` for ephemeral messages, and use search for past encrypted chats.

4. **Switch to Relay Mode (Optional)**  
   When across different networks, start the relay and connect clients through WebSocket.

---

## 🧬 Tech Stack

- **Language:** Python 3.10+  
- **Crypto:** AES-GCM, X25519, HKDF, HMAC  
- **Frameworks:** Typer (CLI), FastAPI (Relay)  
- **Database:** SQLite (encrypted message storage)

---

## 🧰 Deliverables

- 🤩 Fully modular package (`secure_chat/`)  
- 🗾 CLI interface for server, client, search  
- 🤓 Secure, AEAD-based encryption  
- 🌍 Optional WebSocket relay for internet communication  
- 🔒 Local searchable encrypted chat history  

---

## 📜 License

This project is released under the **MIT License**.  
Feel free to fork, modify, and improve!

---

## 👨‍💻 Author

**Sri Charan** — Passionate about cybersecurity, cryptography, and secure communication systems.

