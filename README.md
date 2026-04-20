# 🔐 Proxy Re-Encryption IoT Security System
### A Proxy Re-Encryption Approach to Secure Data Sharing in IoT Based on Blockchain

---

## 📌 Project Overview

This is a full-stack web application that simulates a **Proxy Re-Encryption (PRE)** based secure file sharing system for IoT environments. It is built with:

- **Backend**: Python + Flask
- **Database**: SQLite (via Python's built-in `sqlite3`)
- **Frontend**: HTML, CSS (custom), JavaScript
- **Encryption**: AES-256-CBC (via `pycryptodome`)

---

## 🗂 Project Structure

```
proxy_reencryption/
│
├── app.py                  ← Main Flask application (all routes)
├── requirements.txt        ← Python dependencies
│
├── models/
│   ├── db.py               ← Database setup, table creation, activity logging
│   └── crypto.py           ← AES-256 encryption/decryption + key generation
│
├── templates/              ← HTML pages (Jinja2 templates)
│   ├── base.html           ← Shared layout (header, footer, nav)
│   ├── home.html           ← Landing page
│   │
│   ├── owner_login.html    ← Data Owner login
│   ├── owner_register.html ← Data Owner registration
│   ├── owner_home.html     ← Data Owner dashboard
│   ├── owner_upload.html   ← File upload + encryption
│   ├── owner_myfiles.html  ← View my uploaded files
│   ├── owner_requests.html ← Approve/reject access requests
│   │
│   ├── user_login.html     ← Data User login
│   ├── user_register.html  ← Data User registration
│   ├── user_home.html      ← Data User dashboard
│   ├── user_search.html    ← Search files by keyword
│   ├── user_requests.html  ← View my requests + download
│   │
│   ├── ta_login.html       ← Trusted Authority login
│   ├── ta_home.html        ← TA dashboard
│   ├── ta_owners.html      ← Manage data owners
│   ├── ta_users.html       ← Manage data users
│   ├── ta_requests.html    ← View all file requests
│   │
│   ├── proxy_login.html    ← Proxy Server login
│   ├── proxy_home.html     ← Proxy dashboard
│   ├── proxy_uploaded.html ← View all uploaded files
│   ├── proxy_requests.html ← Re-encrypt & deliver files
│   │
│   ├── csp_login.html      ← CSP login
│   ├── csp_home.html       ← CSP dashboard (with stats)
│   ├── csp_files.html      ← View all cloud files
│   ├── csp_analytics.html  ← Charts & analytics (EXTRA FEATURE)
│   └── csp_logs.html       ← Activity audit log (EXTRA FEATURE)
│
├── static/
│   ├── css/style.css       ← Full custom stylesheet
│   ├── js/main.js          ← Blockchain terminal + utilities
│   └── uploads/            ← Encrypted files stored here
│
└── database/
    └── proxy.db            ← SQLite database (auto-created on first run)
```

---

## ⚙️ Setup Instructions

### Step 1 — Install Python
Make sure Python 3.8 or higher is installed:
```bash
python --version
```

### Step 2 — (Optional) Create a Virtual Environment
```bash
python -m venv venv

# On Windows:
venv\Scripts\activate

# On Mac/Linux:
source venv/bin/activate
```

### Step 3 — Install Dependencies
```bash
pip install -r requirements.txt
```

### Step 4 — Run the App
```bash
python app.py
```

### Step 5 — Open in Browser
Visit: **http://127.0.0.1:5000**

---

## 🔑 Login Credentials

### Special Roles (hardcoded):
| Role | Email | Password |
|------|-------|----------|
| Trusted Authority | ta@admin.com | ta123 |
| Proxy Server | proxy@admin.com | proxy123 |
| Cloud (CSP) | csp@admin.com | csp123 |

### Data Owner / Data User:
Register a new account through the Register button on the login page.

---

## 👥 Roles & Workflow

### 1. Data Owner
- Register and log in
- Upload a file → auto-encrypted with **AES-256**
- View uploaded files with encryption keys
- Approve or reject access requests from data users

### 2. Data User
- Register and log in
- **Search** for files by keyword
- Send a request to the data owner
- Once approved → **Download** the decrypted file

### 3. Trusted Authority (TA)
- Log in with admin credentials
- View all registered owners and users
- **Activate / Deactivate** accounts
- View all file access requests

### 4. Proxy Server
- Log in with admin credentials
- View all uploaded files
- **Re-Encrypt & Deliver** approved files to data users

### 5. Cloud Service Provider (CSP)
- Log in with admin credentials
- View all cloud-stored files
- View **Analytics Charts** (files per owner, request status)
- View full **Activity Audit Log**

---

## ✨ Extra Features Added

### 1. 📊 Analytics Dashboard (CSP)
**Why:** Gives the cloud provider visibility into system usage patterns.
**How:** Bar chart (files per owner) + doughnut chart (request status) using Chart.js, fed from a `/api/chart-data` JSON endpoint.

### 2. 📜 Activity Audit Log (CSP)
**Why:** Improves security accountability — every login, upload, request, and download is recorded.
**How:** A dedicated `activity_log` table in SQLite. A `log_activity()` helper is called at every key action in `app.py`. The CSP can search/filter logs in real time.

### 3. 🔍 File Search by Keyword (Data User)
**Why:** Makes the system actually usable — users need to find files without knowing exact names.
**How:** SQL `LIKE` query on both `keyword` and `filename` columns. The search bar supports partial matches.

---

## 🔒 Security Notes

- Passwords are stored as plain text for simplicity (this is a college project demo).
  In production, use `werkzeug.security.generate_password_hash`.
- File encryption uses real **AES-256-CBC** via the `pycryptodome` library.
- Keys are randomly generated using Python's `secrets` module.
- The blockchain terminal is simulated for demonstration; a real implementation would use Ethereum or Hyperledger.

---

## 📦 Dependencies

| Package | Purpose |
|---------|---------|
| Flask | Web framework |
| Werkzeug | Utilities (file upload security) |
| pycryptodome | AES-256 encryption/decryption |

---

*Built for academic demonstration of Proxy Re-Encryption in IoT environments.*
