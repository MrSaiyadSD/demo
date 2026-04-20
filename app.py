# app.py
# Main entry point for the Proxy Re-Encryption IoT Security Web Application.
# Run this file to start the Flask development server.

import os
import io
from flask import (
    Flask, render_template, request, redirect,
    url_for, session, flash, send_file, jsonify
)
from werkzeug.utils import secure_filename
from models.db import init_db, get_db, log_activity
from models.crypto import generate_key_pair, encrypt_file, decrypt_file

# ─── App Configuration ────────────────────────────────────────────────────────
app = Flask(__name__)
app.secret_key = 'proxy_re_encryption_secret_2026'   # Change in production!

UPLOAD_FOLDER = os.path.join('static', 'uploads')
ALLOWED_EXTENSIONS = {'txt', 'pdf', 'png', 'jpg', 'jpeg', 'docx', 'csv'}
MAX_CONTENT_LENGTH = 16 * 1024 * 1024   # 16 MB max upload size

app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER
app.config['MAX_CONTENT_LENGTH'] = MAX_CONTENT_LENGTH

# Hardcoded credentials for special roles (Trusted Authority, Proxy, CSP)
TA_EMAIL    = 'ta@admin.com'
TA_PASSWORD = 'ta123'
PROXY_EMAIL    = 'proxy@admin.com'
PROXY_PASSWORD = 'proxy123'
CSP_EMAIL    = 'csp@admin.com'
CSP_PASSWORD = 'csp123'


def allowed_file(filename):
    """Check if the uploaded file has an allowed extension."""
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS


# ─── Home / Landing Page ──────────────────────────────────────────────────────
@app.route('/')
def home():
    return render_template('home.html')


# ═══════════════════════════════════════════════════════════════════════════════
# DATA OWNER ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/owner/login', methods=['GET', 'POST'])
def owner_login():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('owner_login.html')

        conn = get_db()
        owner = conn.execute(
            "SELECT * FROM data_owners WHERE email=? AND password=? AND status='Activated'",
            (email, password)
        ).fetchone()
        conn.close()

        if owner:
            # Store owner info in session
            session['owner_id']   = owner['id']
            session['owner_name'] = owner['username']
            session['role']       = 'owner'
            log_activity(owner['username'], 'data_owner', 'Login', f"Email: {email}")
            return redirect(url_for('owner_home'))
        else:
            flash('Invalid credentials or account not activated.', 'error')

    return render_template('owner_login.html')


@app.route('/owner/register', methods=['GET', 'POST'])
def owner_register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        mobile   = request.form.get('mobile', '').strip()
        gender   = request.form.get('gender', '').strip()
        dob      = request.form.get('dob', '').strip()
        location = request.form.get('location', '').strip()

        # Basic validation
        if not all([username, email, password]):
            flash('Username, email and password are required.', 'error')
            return render_template('owner_register.html')

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO data_owners (username,email,password,mobile,gender,dob,location) VALUES (?,?,?,?,?,?,?)",
                (username, email, password, mobile, gender, dob, location)
            )
            conn.commit()
            conn.close()
            log_activity(username, 'data_owner', 'Register', f"Email: {email}")
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('owner_login'))
        except Exception:
            flash('Email or username already registered.', 'error')

    return render_template('owner_register.html')


@app.route('/owner/home')
def owner_home():
    if session.get('role') != 'owner':
        return redirect(url_for('owner_login'))
    return render_template('owner_home.html', name=session['owner_name'])


@app.route('/owner/upload', methods=['GET', 'POST'])
def owner_upload():
    if session.get('role') != 'owner':
        return redirect(url_for('owner_login'))

    if request.method == 'POST':
        keyword = request.form.get('keyword', '').strip()
        file    = request.files.get('file')

        if not keyword or not file or file.filename == '':
            flash('Keyword and file are required.', 'error')
            return render_template('owner_upload.html')

        if not allowed_file(file.filename):
            flash('File type not allowed.', 'error')
            return render_template('owner_upload.html')

        filename = secure_filename(file.filename)
        file_bytes = file.read()

        # Generate encryption keys
        tkey, skey = generate_key_pair()

        # Encrypt the file
        encrypted = encrypt_file(file_bytes, tkey)

        # Save encrypted file to disk
        save_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        with open(save_path, 'wb') as f:
            f.write(encrypted)

        # Save record to database
        conn = get_db()
        owner = conn.execute("SELECT * FROM data_owners WHERE id=?", (session['owner_id'],)).fetchone()
        conn.execute(
            "INSERT INTO uploaded_files (owner_id,username,email,keyword,tkey,skey,filename) VALUES (?,?,?,?,?,?,?)",
            (session['owner_id'], session['owner_name'], owner['email'], keyword, tkey, skey, filename)
        )
        conn.commit()
        conn.close()

        log_activity(session['owner_name'], 'data_owner', 'Upload File', f"File: {filename}, Keyword: {keyword}")
        flash(f'File "{filename}" uploaded and encrypted successfully!', 'success')
        return redirect(url_for('owner_my_files'))

    return render_template('owner_upload.html')


@app.route('/owner/myfiles')
def owner_my_files():
    if session.get('role') != 'owner':
        return redirect(url_for('owner_login'))

    conn  = get_db()
    files = conn.execute(
        "SELECT * FROM uploaded_files WHERE owner_id=? ORDER BY uploaded_at DESC",
        (session['owner_id'],)
    ).fetchall()
    conn.close()
    return render_template('owner_myfiles.html', files=files)


@app.route('/owner/requests')
def owner_requests():
    if session.get('role') != 'owner':
        return redirect(url_for('owner_login'))

    conn = get_db()
    reqs = conn.execute(
        "SELECT * FROM file_requests WHERE owner_id=? ORDER BY requested_at DESC",
        (session['owner_id'],)
    ).fetchall()
    conn.close()
    return render_template('owner_requests.html', requests=reqs)


@app.route('/owner/approve/<int:req_id>')
def owner_approve(req_id):
    if session.get('role') != 'owner':
        return redirect(url_for('owner_login'))

    conn = get_db()
    req  = conn.execute("SELECT * FROM file_requests WHERE sno=?", (req_id,)).fetchone()

    if req:
        conn.execute(
            "UPDATE file_requests SET req_status='Accept' WHERE sno=?",
            (req_id,)
        )
        conn.commit()
        log_activity(session['owner_name'], 'data_owner', 'Approve Request',
                     f"Request #{req_id}, File: {req['filename']}, User: {req['user_name']}")
    conn.close()
    flash('Request approved successfully!', 'success')
    return redirect(url_for('owner_requests'))


@app.route('/owner/reject/<int:req_id>')
def owner_reject(req_id):
    if session.get('role') != 'owner':
        return redirect(url_for('owner_login'))

    conn = get_db()
    conn.execute("UPDATE file_requests SET req_status='Reject' WHERE sno=?", (req_id,))
    conn.commit()
    log_activity(session['owner_name'], 'data_owner', 'Reject Request', f"Request #{req_id}")
    conn.close()
    flash('Request rejected.', 'info')
    return redirect(url_for('owner_requests'))


@app.route('/owner/logout')
def owner_logout():
    log_activity(session.get('owner_name', '?'), 'data_owner', 'Logout')
    session.clear()
    return redirect(url_for('owner_login'))


# ═══════════════════════════════════════════════════════════════════════════════
# DATA USER ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/user/login', methods=['GET', 'POST'])
def user_login():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if not email or not password:
            flash('Please fill in all fields.', 'error')
            return render_template('user_login.html')

        conn = get_db()
        user = conn.execute(
            "SELECT * FROM data_users WHERE email=? AND password=? AND status='Activated'",
            (email, password)
        ).fetchone()
        conn.close()

        if user:
            session['user_id']   = user['id']
            session['user_name'] = user['username']
            session['role']      = 'user'
            log_activity(user['username'], 'data_user', 'Login', f"Email: {email}")
            return redirect(url_for('user_home'))
        else:
            flash('Invalid credentials or account not activated.', 'error')

    return render_template('user_login.html')


@app.route('/user/register', methods=['GET', 'POST'])
def user_register():
    if request.method == 'POST':
        username = request.form.get('username', '').strip()
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()
        mobile   = request.form.get('mobile', '').strip()
        gender   = request.form.get('gender', '').strip()
        dob      = request.form.get('dob', '').strip()
        location = request.form.get('location', '').strip()

        if not all([username, email, password]):
            flash('Username, email and password are required.', 'error')
            return render_template('user_register.html')

        try:
            conn = get_db()
            conn.execute(
                "INSERT INTO data_users (username,email,password,mobile,gender,dob,location) VALUES (?,?,?,?,?,?,?)",
                (username, email, password, mobile, gender, dob, location)
            )
            conn.commit()
            conn.close()
            log_activity(username, 'data_user', 'Register', f"Email: {email}")
            flash('Registration successful! You can now log in.', 'success')
            return redirect(url_for('user_login'))
        except Exception:
            flash('Email or username already registered.', 'error')

    return render_template('user_register.html')


@app.route('/user/home')
def user_home():
    if session.get('role') != 'user':
        return redirect(url_for('user_login'))
    return render_template('user_home.html', name=session['user_name'])


@app.route('/user/search')
def user_search():
    if session.get('role') != 'user':
        return redirect(url_for('user_login'))

    query   = request.args.get('q', '').strip()
    results = []

    if query:
        conn    = get_db()
        results = conn.execute(
            "SELECT * FROM uploaded_files WHERE keyword LIKE ? OR filename LIKE ?",
            (f'%{query}%', f'%{query}%')
        ).fetchall()
        conn.close()
        log_activity(session['user_name'], 'data_user', 'Search', f"Query: {query}")

    return render_template('user_search.html', results=results, query=query)


@app.route('/user/request/<int:file_id>')
def user_request_file(file_id):
    if session.get('role') != 'user':
        return redirect(url_for('user_login'))

    conn  = get_db()
    ufile = conn.execute("SELECT * FROM uploaded_files WHERE sno=?", (file_id,)).fetchone()
    user  = conn.execute("SELECT * FROM data_users WHERE id=?", (session['user_id'],)).fetchone()

    if not ufile:
        flash('File not found.', 'error')
        conn.close()
        return redirect(url_for('user_search'))

    # Check if already requested
    existing = conn.execute(
        "SELECT * FROM file_requests WHERE file_id=? AND user_id=?",
        (file_id, session['user_id'])
    ).fetchone()

    if existing:
        flash('You have already requested this file.', 'info')
    else:
        conn.execute(
            '''INSERT INTO file_requests
               (file_id,owner_id,owner_name,user_id,user_name,user_email,keyword,filename,tkey,skey)
               VALUES (?,?,?,?,?,?,?,?,?,?)''',
            (file_id, ufile['owner_id'], ufile['username'],
             session['user_id'], session['user_name'], user['email'],
             ufile['keyword'], ufile['filename'], ufile['tkey'], ufile['skey'])
        )
        conn.commit()
        log_activity(session['user_name'], 'data_user', 'Request File',
                     f"File: {ufile['filename']} from Owner: {ufile['username']}")
        flash(f'Request sent for "{ufile["filename"]}"!', 'success')

    conn.close()
    return redirect(url_for('user_my_requests'))


@app.route('/user/myrequests')
def user_my_requests():
    if session.get('role') != 'user':
        return redirect(url_for('user_login'))

    conn = get_db()
    reqs = conn.execute(
        "SELECT * FROM file_requests WHERE user_id=? ORDER BY requested_at DESC",
        (session['user_id'],)
    ).fetchall()
    conn.close()
    return render_template('user_requests.html', requests=reqs)


@app.route('/user/download/<int:req_id>')
def user_download(req_id):
    """
    Allow a data user to download a file if the request has been accepted
    and delivered by the proxy server.
    """
    if session.get('role') != 'user':
        return redirect(url_for('user_login'))

    conn = get_db()
    req  = conn.execute(
        "SELECT * FROM file_requests WHERE sno=? AND user_id=?",
        (req_id, session['user_id'])
    ).fetchone()
    conn.close()

    if not req:
        flash('Request not found.', 'error')
        return redirect(url_for('user_my_requests'))

    if req['req_status'] != 'Accept':
        flash('Your request has not been approved yet.', 'info')
        return redirect(url_for('user_my_requests'))

    # Read encrypted file from disk
    filepath = os.path.join(app.config['UPLOAD_FOLDER'], req['filename'])
    if not os.path.exists(filepath):
        flash('File not found on server.', 'error')
        return redirect(url_for('user_my_requests'))

    with open(filepath, 'rb') as f:
        encrypted = f.read()

    # Decrypt using the stored transformation key
    decrypted = decrypt_file(encrypted, req['tkey'])

    if decrypted is None:
        flash('Decryption failed. Please contact the administrator.', 'error')
        return redirect(url_for('user_my_requests'))

    log_activity(session['user_name'], 'data_user', 'Download File', f"File: {req['filename']}")

    return send_file(
        io.BytesIO(decrypted),
        download_name=req['filename'],
        as_attachment=True
    )


@app.route('/user/logout')
def user_logout():
    log_activity(session.get('user_name', '?'), 'data_user', 'Logout')
    session.clear()
    return redirect(url_for('user_login'))


# ═══════════════════════════════════════════════════════════════════════════════
# TRUSTED AUTHORITY (TA) ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/ta/login', methods=['GET', 'POST'])
def ta_login():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if email == TA_EMAIL and password == TA_PASSWORD:
            session['role']    = 'ta'
            session['ta_name'] = 'Trusted Authority'
            log_activity('TA', 'ta', 'Login')
            return redirect(url_for('ta_home'))
        else:
            flash('Invalid credentials.', 'error')

    return render_template('ta_login.html')


@app.route('/ta/home')
def ta_home():
    if session.get('role') != 'ta':
        return redirect(url_for('ta_login'))
    return render_template('ta_home.html')


@app.route('/ta/owners')
def ta_owners():
    if session.get('role') != 'ta':
        return redirect(url_for('ta_login'))
    conn    = get_db()
    owners  = conn.execute("SELECT * FROM data_owners ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('ta_owners.html', owners=owners)


@app.route('/ta/users')
def ta_users():
    if session.get('role') != 'ta':
        return redirect(url_for('ta_login'))
    conn  = get_db()
    users = conn.execute("SELECT * FROM data_users ORDER BY created_at DESC").fetchall()
    conn.close()
    return render_template('ta_users.html', users=users)


@app.route('/ta/requests')
def ta_requests():
    if session.get('role') != 'ta':
        return redirect(url_for('ta_login'))
    conn = get_db()
    reqs = conn.execute("SELECT * FROM file_requests ORDER BY requested_at DESC").fetchall()
    conn.close()
    return render_template('ta_requests.html', requests=reqs)


@app.route('/ta/toggle_owner/<int:owner_id>')
def ta_toggle_owner(owner_id):
    if session.get('role') != 'ta':
        return redirect(url_for('ta_login'))
    conn  = get_db()
    owner = conn.execute("SELECT status FROM data_owners WHERE id=?", (owner_id,)).fetchone()
    new_status = 'Deactivated' if owner['status'] == 'Activated' else 'Activated'
    conn.execute("UPDATE data_owners SET status=? WHERE id=?", (new_status, owner_id))
    conn.commit()
    conn.close()
    log_activity('TA', 'ta', f'Toggle Owner Status → {new_status}', f"Owner ID: {owner_id}")
    flash(f'Owner status changed to {new_status}.', 'success')
    return redirect(url_for('ta_owners'))


@app.route('/ta/toggle_user/<int:user_id>')
def ta_toggle_user(user_id):
    if session.get('role') != 'ta':
        return redirect(url_for('ta_login'))
    conn  = get_db()
    user  = conn.execute("SELECT status FROM data_users WHERE id=?", (user_id,)).fetchone()
    new_status = 'Deactivated' if user['status'] == 'Activated' else 'Activated'
    conn.execute("UPDATE data_users SET status=? WHERE id=?", (new_status, user_id))
    conn.commit()
    conn.close()
    flash(f'User status changed to {new_status}.', 'success')
    return redirect(url_for('ta_users'))


@app.route('/ta/logout')
def ta_logout():
    log_activity('TA', 'ta', 'Logout')
    session.clear()
    return redirect(url_for('ta_login'))


# ═══════════════════════════════════════════════════════════════════════════════
# PROXY SERVER ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/proxy/login', methods=['GET', 'POST'])
def proxy_login():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if email == PROXY_EMAIL and password == PROXY_PASSWORD:
            session['role']       = 'proxy'
            session['proxy_name'] = 'Proxy Server'
            log_activity('Proxy', 'proxy', 'Login')
            return redirect(url_for('proxy_home'))
        else:
            flash('Invalid credentials.', 'error')

    return render_template('proxy_login.html')


@app.route('/proxy/home')
def proxy_home():
    if session.get('role') != 'proxy':
        return redirect(url_for('proxy_login'))
    return render_template('proxy_home.html')


@app.route('/proxy/uploaded')
def proxy_uploaded():
    if session.get('role') != 'proxy':
        return redirect(url_for('proxy_login'))
    conn   = get_db()
    files  = conn.execute("SELECT * FROM uploaded_files ORDER BY uploaded_at DESC").fetchall()
    conn.close()
    return render_template('proxy_uploaded.html', files=files)


@app.route('/proxy/requests')
def proxy_requests():
    if session.get('role') != 'proxy':
        return redirect(url_for('proxy_login'))
    conn = get_db()
    reqs = conn.execute(
        "SELECT * FROM file_requests WHERE req_status='Accept' ORDER BY requested_at DESC"
    ).fetchall()
    conn.close()
    return render_template('proxy_requests.html', requests=reqs)


@app.route('/proxy/deliver/<int:req_id>')
def proxy_deliver(req_id):
    """Mark a request as 'Delivery' — the proxy has re-encrypted and forwarded the file."""
    if session.get('role') != 'proxy':
        return redirect(url_for('proxy_login'))

    conn = get_db()
    req  = conn.execute("SELECT * FROM file_requests WHERE sno=?", (req_id,)).fetchone()
    if req:
        conn.execute("UPDATE file_requests SET d_status='Delivery' WHERE sno=?", (req_id,))
        conn.commit()
        log_activity('Proxy', 'proxy', 'Deliver File',
                     f"File: {req['filename']} to User: {req['user_name']}")
    conn.close()
    flash('File delivered to data user!', 'success')
    return redirect(url_for('proxy_requests'))


@app.route('/proxy/logout')
def proxy_logout():
    log_activity('Proxy', 'proxy', 'Logout')
    session.clear()
    return redirect(url_for('proxy_login'))


# ═══════════════════════════════════════════════════════════════════════════════
# CLOUD SERVICE PROVIDER (CSP) ROUTES
# ═══════════════════════════════════════════════════════════════════════════════

@app.route('/csp/login', methods=['GET', 'POST'])
def csp_login():
    if request.method == 'POST':
        email    = request.form.get('email', '').strip()
        password = request.form.get('password', '').strip()

        if email == CSP_EMAIL and password == CSP_PASSWORD:
            session['role']     = 'csp'
            session['csp_name'] = 'Cloud Service Provider'
            log_activity('CSP', 'csp', 'Login')
            return redirect(url_for('csp_home'))
        else:
            flash('Invalid credentials.', 'error')

    return render_template('csp_login.html')


@app.route('/csp/home')
def csp_home():
    if session.get('role') != 'csp':
        return redirect(url_for('csp_login'))

    conn   = get_db()
    total_files  = conn.execute("SELECT COUNT(*) as c FROM uploaded_files").fetchone()['c']
    total_owners = conn.execute("SELECT COUNT(*) as c FROM data_owners").fetchone()['c']
    total_users  = conn.execute("SELECT COUNT(*) as c FROM data_users").fetchone()['c']
    total_reqs   = conn.execute("SELECT COUNT(*) as c FROM file_requests").fetchone()['c']
    conn.close()

    stats = {
        'files': total_files,
        'owners': total_owners,
        'users': total_users,
        'requests': total_reqs
    }
    return render_template('csp_home.html', stats=stats)


@app.route('/csp/files')
def csp_files():
    if session.get('role') != 'csp':
        return redirect(url_for('csp_login'))
    conn   = get_db()
    files  = conn.execute("SELECT * FROM uploaded_files ORDER BY uploaded_at DESC").fetchall()
    conn.close()
    return render_template('csp_files.html', files=files)


@app.route('/csp/analytics')
def csp_analytics():
    """Extra Feature: Analytics/Charts dashboard for the CSP."""
    if session.get('role') != 'csp':
        return redirect(url_for('csp_login'))

    conn = get_db()
    # Files uploaded per owner
    by_owner = conn.execute(
        "SELECT username, COUNT(*) as cnt FROM uploaded_files GROUP BY username"
    ).fetchall()
    # Request status breakdown
    by_status = conn.execute(
        "SELECT req_status, COUNT(*) as cnt FROM file_requests GROUP BY req_status"
    ).fetchall()
    conn.close()

    return render_template('csp_analytics.html',
                           by_owner=by_owner, by_status=by_status)


@app.route('/csp/logs')
def csp_logs():
    """Extra Feature: Activity audit log."""
    if session.get('role') != 'csp':
        return redirect(url_for('csp_login'))

    conn  = get_db()
    logs  = conn.execute("SELECT * FROM activity_log ORDER BY logged_at DESC LIMIT 200").fetchall()
    conn.close()
    return render_template('csp_logs.html', logs=logs)


@app.route('/csp/logout')
def csp_logout():
    log_activity('CSP', 'csp', 'Logout')
    session.clear()
    return redirect(url_for('csp_login'))


# ─── API: Analytics data for charts (JSON) ────────────────────────────────────
@app.route('/api/chart-data')
def chart_data():
    """Returns JSON used by Chart.js on the analytics page."""
    if session.get('role') != 'csp':
        return jsonify({'error': 'Unauthorised'}), 403

    conn     = get_db()
    by_owner = conn.execute(
        "SELECT username, COUNT(*) as cnt FROM uploaded_files GROUP BY username"
    ).fetchall()
    by_status = conn.execute(
        "SELECT req_status, COUNT(*) as cnt FROM file_requests GROUP BY req_status"
    ).fetchall()
    conn.close()

    return jsonify({
        'owners': {
            'labels': [r['username'] for r in by_owner],
            'data':   [r['cnt']      for r in by_owner]
        },
        'statuses': {
            'labels': [r['req_status'] for r in by_status],
            'data':   [r['cnt']        for r in by_status]
        }
    })


# ─── Run the app ──────────────────────────────────────────────────────────────
if __name__ == '__main__':
    # Make sure the uploads folder exists
    os.makedirs(UPLOAD_FOLDER, exist_ok=True)
    # Initialise the database (creates tables if they don't exist)
    init_db()
    print("\n" + "="*55)
    print("  Proxy Re-Encryption IoT Security App")
    print("  Running at: http://127.0.0.1:5000")
    print("="*55 + "\n")
    app.run(debug=True, port=5000)
