# --- START OF FILE index.py ---

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response
from functools import wraps
import sqlite3
import os
import hashlib # FIX: Import hashlib at the top
from datetime import datetime, timedelta
import uuid
import traceback
import markdown
import time
from collections import Counter
import re
import io
import csv
import base64
import gdrive

# Document/Web Parsing Libraries
import ollama
import pdfplumber
from bs4 import BeautifulSoup
import requests
import docx

# --- Setup credentials from environment variable ---
if 'GOOGLE_CREDENTIALS_BASE64' in os.environ:
    creds_base64 = os.environ['GOOGLE_CREDENTIALS_BASE64']
    creds_json = base64.b64decode(creds_base64).decode('utf-8')
    with open('credentials.json', 'w') as f:
        f.write(creds_json)

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-very-secret-key-that-is-long-and-secure')
DATABASE = 'policy_chatbot.db'
# This is now just a temporary location for file uploads before they go to GDrive
UPLOAD_FOLDER = 'temp_uploads' 
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'pdf', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Database Initialization ---
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, login_timestamp DATETIME, failed_attempts INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY, filename TEXT NOT NULL, display_name TEXT NOT NULL, filetype TEXT NOT NULL, filesize INTEGER NOT NULL, upload_timestamp DATETIME, uploaded_by INTEGER, FOREIGN KEY(uploaded_by) REFERENCES users(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY, client_id INTEGER, api_key TEXT NOT NULL, purpose TEXT, issuance_timestamp DATETIME, FOREIGN KEY(client_id) REFERENCES users(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS interactions (id INTEGER PRIMARY KEY, user_query TEXT, ai_response TEXT, timestamp DATETIME, feedback_score INTEGER, feedback_comment TEXT, response_id TEXT, response_time_seconds REAL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS glossary (id INTEGER PRIMARY KEY AUTOINCREMENT, term TEXT UNIQUE NOT NULL, definition TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)''')
        
        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', hash_password('admin123'), 'admin'))
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('client', hash_password('client123'), 'client'))

        c.execute("INSERT OR IGNORE INTO api_keys (id, client_id, api_key, purpose, issuance_timestamp) VALUES (?, ?, ?, ?, ?)", (1, 2, '11111111-1111-1111-1111-111111111111', 'Default Key for Policy Page Demo', datetime.now().isoformat()))

        if c.execute("SELECT COUNT(*) FROM glossary").fetchone()[0] == 0:
            sample_terms = [('GDPR', 'The General Data Protection Regulation is a regulation in EU law on data protection and privacy.'), ('Cookies', 'Small files stored on a user\'s computer by their web browser at the request of a website.'), ('Personal Data', 'Any information that relates to an identified or identifiable individual.'), ('Third-party', 'An entity other than the user or the service provider, who may receive user data.')]
            c.executemany("INSERT INTO glossary (term, definition) VALUES (?, ?)", sample_terms)
        
        conn.commit()

def init_settings():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('chatbot_enabled', 'true'))
        c.execute("INSERT OR IGNORE INTO settings (key, value) VALUES (?, ?)", ('chatbot_timeout', '5m'))
        conn.commit()

# --- Utility Functions ---
def get_db_connection():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_pdf(file_stream):
    text = ""
    with pdfplumber.open(file_stream) as pdf:
        for page in pdf.pages:
            text += page.extract_text() or ""
    return text

def extract_text_from_docx(file_stream):
    doc = docx.Document(file_stream)
    return "\n".join([para.text for para in doc.paragraphs])

def extract_text_from_url(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        for element in soup(['script', 'style', 'nav', 'header', 'footer']): element.extract()
        return " ".join(text for text in soup.stripped_strings if text)
    except requests.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return None

def get_knowledge_base_content(client_id=None):
    conn = get_db_connection()
    # Query for documents uploaded by the admin (global docs)
    admin_docs_query = 'SELECT filename, display_name, filetype, upload_timestamp FROM documents WHERE uploaded_by = 1 ORDER BY upload_timestamp ASC'
    admin_docs = conn.execute(admin_docs_query).fetchall()
    
    client_docs = []
    if client_id:
        # Query for documents uploaded by the specific client
        client_docs_query = 'SELECT filename, display_name, filetype, upload_timestamp FROM documents WHERE uploaded_by = ? ORDER BY upload_timestamp ASC'
        client_docs = conn.execute(client_docs_query, (client_id,)).fetchall()
    
    conn.close()
    
    def compile_text(documents):
        text_block = ""
        for doc in documents:
            file_id, display_name, timestamp_str = doc['filename'], doc['display_name'], doc['upload_timestamp'].split('T')[0]
            try:
                file_stream = gdrive.download_file(file_id)
                content = ""
                if doc['filetype'] == 'pdf': content = extract_text_from_pdf(file_stream)
                elif doc['filetype'] == 'docx': content = extract_text_from_docx(file_stream)
                if content:
                    text_block += f"\n\n--- Document: {display_name} (Uploaded: {timestamp_str}) ---\n{content}"
            except Exception as e:
                print(f"Error reading document {display_name} (ID: {file_id}) from Drive: {e}")
        return text_block.strip()

    admin_kb = compile_text(admin_docs)
    client_kb = compile_text(client_docs)
    
    return admin_kb, client_kb

def get_settings():
    conn = get_db_connection()
    settings_data = conn.execute('SELECT key, value FROM settings').fetchall()
    conn.close()
    return {row['key']: row['value'] for row in settings_data}

# --- AUTHENTICATION DECORATOR ---
def login_required(role="ANY"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))
            
            # FIX: Verify user still exists in the database
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            conn.close()
            
            if not user:
                session.clear()
                flash('Your user account could not be found. Please log in again.', 'danger')
                return redirect(url_for('login'))

            if role != "ANY" and user['role'] != role:
                flash('You do not have permission to access that page.', 'danger')
                # Redirect to their own dashboard
                return redirect(url_for(f"{user['role']}_dashboard"))
            
            return f(*args, **kwargs)
        return decorated_function
    return decorator


# --- CORE & LOGIN ROUTES ---

@app.route('/')
def home():
    # This is the new public-facing homepage
    return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    # If user is already logged in, redirect them to their dashboard
    if 'user_id' in session:
        role = session.get('role', 'client') # Default to client if role isn't set
        return redirect(url_for(f'{role}_dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        conn.close()
        
        is_password_correct = user_data and (user_data['password'] == hashed_password)

        if is_password_correct:
            user = dict(user_data)
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']
            
            with get_db_connection() as conn:
                conn.execute('UPDATE users SET login_timestamp = ?, failed_attempts = 0 WHERE id = ?', (datetime.now(), user['id']))
                conn.commit()
            
            flash(f'Welcome, {user["username"]}!', 'success')
            return redirect(url_for(f"{user['role']}_dashboard"))
        else:
            if user_data:
                with get_db_connection() as conn:
                    conn.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?', (user_data['id'],))
                    conn.commit()
            flash('Invalid username or password.', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required()
def logout():
    session.clear()
    flash('You have been logged out successfully.', 'info')
    return redirect(url_for('login'))

@app.route('/lumon/signup')
def lumon_signup():
    settings = get_settings()
    # The widget will only appear on this page.
    return render_template('severance_signup.html', settings=settings, show_widget=True)

# @app.route('/policy-page')
# def policy_example():
#     settings = get_settings()
#     content = "This is a demonstration page for the Policy Insight chatbot. Ask a question to begin."
#     return render_template('policy_page.html', content=content, settings=settings)

# --- ADMIN ROUTES ---
@app.route('/admin/')
@login_required(role="admin")
def admin_index():
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/dashboard')
@login_required(role="admin")
def admin_dashboard():
    conn = get_db_connection()
    total_docs = conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    queries_today = conn.execute('SELECT COUNT(*) FROM interactions WHERE DATE(timestamp) = DATE(?)', (today_start.isoformat(),)).fetchone()[0]
    avg_response_time = conn.execute('SELECT AVG(response_time_seconds) FROM interactions WHERE response_time_seconds IS NOT NULL').fetchone()[0] or 0
    recent_docs = conn.execute('SELECT display_name, upload_timestamp FROM documents ORDER BY upload_timestamp DESC LIMIT 5').fetchall()
    labels, data = [], []
    for i in range(6, -1, -1):
        day = datetime.now() - timedelta(days=i)
        day_str = day.strftime('%Y-%m-%d')
        labels.append(day.strftime('%a'))
        count = conn.execute('SELECT COUNT(*) FROM interactions WHERE DATE(timestamp) = ?', (day_str,)).fetchone()[0]
        data.append(count)
    conn.close()
    stats = {'total_docs': total_docs, 'queries_today': queries_today, 'avg_response_time': avg_response_time}
    daily_queries = {'labels': labels, 'data': data}
    return render_template('admin_dashboard.html', stats=stats, recent_docs=recent_docs, daily_queries=daily_queries)

@app.route('/admin/documents', methods=['GET', 'POST'])
@login_required(role="admin")
def admin_documents():
    admin_id = session['user_id']
    conn = get_db_connection()
    if request.method == 'POST':
        if 'document' not in request.files or not request.files['document'].filename:
            flash('No file selected', 'warning')
            return redirect(request.url)
        file = request.files['document']
        if not allowed_file(file.filename):
            flash('Invalid file type. Only PDF and DOCX are allowed.', 'danger')
            return redirect(request.url)

        original_filename = file.filename
        file_bytes = file.read()
        file_stream = io.BytesIO(file_bytes)
        filesize = len(file_bytes)
        filetype = original_filename.rsplit('.', 1)[1].lower()
        
        try:
            mimetype = 'application/pdf' if filetype == 'pdf' else 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            drive_file_id = gdrive.upload_file(file_stream, original_filename, mimetype)
            conn.execute('INSERT INTO documents (filename, display_name, filetype, filesize, upload_timestamp, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)',
                         (drive_file_id, original_filename, filetype, filesize, datetime.now().isoformat(), admin_id))
            conn.commit()
            flash('Document uploaded successfully to Global Knowledge Base!', 'success')
        except Exception as e:
            flash(f'Failed to upload to Google Drive: {e}', 'danger')
            traceback.print_exc()
        finally:
            conn.close()
        return redirect(url_for('admin_documents'))
    
    # Show only documents uploaded by any admin (assuming user_id 1 is the main admin)
    documents = conn.execute('SELECT d.* FROM documents d JOIN users u ON d.uploaded_by = u.id WHERE u.role = ? ORDER BY d.upload_timestamp DESC', ('admin',)).fetchall()
    conn.close()
    return render_template('admin_documents.html', documents=documents)

@app.route('/admin/documents/delete/<int:doc_id>', methods=['POST'])
@login_required(role="admin")
def admin_delete_document(doc_id):
    conn = get_db_connection()
    doc = conn.execute('SELECT d.filename, d.display_name FROM documents d JOIN users u ON d.uploaded_by = u.id WHERE d.id = ? AND u.role = ?', (doc_id, 'admin')).fetchone()
    if doc:
        try:
            gdrive.delete_file(doc['filename']) 
            conn.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
            conn.commit()
            flash(f"Document '{doc['display_name']}' deleted successfully.", 'success')
        except Exception as e:
            flash(f"Error deleting document: {e}", 'danger')
    else:
        flash('Document not found or you do not have permission to delete.', 'danger')
    conn.close()
    return redirect(url_for('admin_documents'))

@app.route('/admin/analytics')
@login_required(role="admin")
def admin_analytics():
    conn = get_db_connection()
    interactions = conn.execute('SELECT * FROM interactions ORDER BY timestamp DESC').fetchall()
    feedback_counts = {
        'liked': conn.execute('SELECT COUNT(*) FROM interactions WHERE feedback_score = 1').fetchone()[0],
        'disliked': conn.execute('SELECT COUNT(*) FROM interactions WHERE feedback_score = -1').fetchone()[0],
        'no_rating': conn.execute('SELECT COUNT(*) FROM interactions WHERE feedback_score IS NULL OR feedback_score = 0').fetchone()[0]
    }
    timing_data = conn.execute('SELECT AVG(response_time_seconds), MIN(response_time_seconds), MAX(response_time_seconds) FROM interactions WHERE response_time_seconds IS NOT NULL').fetchone()
    all_queries = conn.execute('SELECT user_query FROM interactions').fetchall()
    words = []
    stop_words = set(['what', 'is', 'the', 'are', 'a', 'an', 'in', 'of', 'for', 'to', 'how', 'do', 'i'])
    for row in all_queries:
        if not row['user_query']: continue
        cleaned_query = re.sub(r'[^\w\s]', '', row['user_query']).lower()
        words.extend([word for word in cleaned_query.split() if word not in stop_words and len(word) > 2])
    popular_terms = [term for term, count in Counter(words).most_common(5)]
    analytics_data = {'feedback_counts': feedback_counts, 'avg_response_time': timing_data[0] or 0, 'min_response_time': timing_data[1] or 0, 'max_response_time': timing_data[2] or 0, 'popular_terms': popular_terms}
    conn.close()
    return render_template('admin_analytics.html', interactions=interactions, analytics=analytics_data)

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required(role="admin")
def admin_settings():
    conn = get_db_connection()
    if request.method == 'POST':
        if 'add_user' in request.form:
            username, password, role = request.form.get('username'), request.form.get('password'), request.form.get('role')
            if username and password and role:
                try:
                    conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hash_password(password), role))
                    conn.commit()
                    flash('User added successfully.', 'success')
                except sqlite3.IntegrityError:
                    flash('Username already exists.', 'danger')
            else:
                flash('All fields are required to add a user.', 'warning')
        elif 'save_settings' in request.form:
            chatbot_enabled = request.form.get('chatbot_enabled')
            chatbot_timeout = request.form.get('chatbot_timeout')
            chatbot_enabled_value = 'true' if chatbot_enabled == 'on' else 'false'
            c = conn.cursor()
            c.execute("UPDATE settings SET value = ? WHERE key = ?", (chatbot_enabled_value, 'chatbot_enabled'))
            c.execute("UPDATE settings SET value = ? WHERE key = ?", (chatbot_timeout, 'chatbot_timeout'))
            conn.commit()
            flash('Chatbot settings updated successfully.', 'success')
        conn.close()
        return redirect(url_for('admin_settings'))

    users = conn.execute('SELECT id, username, role FROM users').fetchall()
    api_keys = conn.execute('''
        SELECT api_keys.id, api_keys.api_key, api_keys.purpose, users.username, api_keys.issuance_timestamp 
        FROM api_keys JOIN users ON api_keys.client_id = users.id
        ORDER BY api_keys.issuance_timestamp DESC
    ''').fetchall()
    current_settings = get_settings()
    conn.close()
    db_info = {'name': 'Google Drive (via API)', 'model': 'phi3:mini'} 
    return render_template('admin_settings.html', users=users, api_keys=api_keys, db_info=db_info, settings=current_settings)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required(role="admin")
def admin_delete_user(user_id):
    if user_id == session.get('user_id'):
        flash('You cannot delete your own account.', 'danger')
        return redirect(url_for('admin_settings'))
    conn = get_db_connection()
    try:
        conn.execute('DELETE FROM api_keys WHERE client_id = ?', (user_id,))
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
        flash('User and their associated API keys have been deleted.', 'success')
    except Exception as e:
        flash(f'Error deleting user: {e}', 'danger')
    finally:
        conn.close()
    return redirect(url_for('admin_settings'))

@app.route('/admin/glossary', methods=['GET', 'POST'])
@login_required(role="admin")
def admin_glossary():
    conn = get_db_connection()
    if request.method == 'POST':
        term, definition = request.form['term'], request.form['definition']
        if term and definition:
            try:
                conn.execute('INSERT INTO glossary (term, definition) VALUES (?, ?)', (term, definition))
                conn.commit()
                flash(f'Term "{term}" added successfully!', 'success')
            except sqlite3.IntegrityError:
                flash(f'Term "{term}" already exists.', 'danger')
        else:
            flash('Both term and definition are required.', 'warning')
        return redirect(url_for('admin_glossary'))
    glossary_terms = conn.execute('SELECT * FROM glossary ORDER BY term').fetchall()
    conn.close()
    return render_template('admin_glossary.html', glossary_terms=glossary_terms)

@app.route('/admin/glossary/delete/<int:term_id>', methods=['POST'])
@login_required(role="admin")
def admin_delete_term(term_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM glossary WHERE id = ?', (term_id,))
    conn.commit()
    conn.close()
    flash('Term deleted successfully.', 'success')
    return redirect(url_for('admin_glossary'))

# --- CLIENT ROUTES ---
@app.route('/client/dashboard')
@login_required(role="client")
def client_dashboard():
    client_id = session['user_id']
    conn = get_db_connection()
    # Placeholder analytics
    queries_today = conn.execute('SELECT COUNT(*) FROM interactions WHERE DATE(timestamp) = DATE("now")').fetchone()[0]
    queries_this_month = conn.execute('SELECT COUNT(*) FROM interactions WHERE STRFTIME("%Y-%m", timestamp) = STRFTIME("%Y-%m", "now")').fetchone()[0]
    api_key_count = conn.execute('SELECT COUNT(*) FROM api_keys WHERE client_id = ?', (client_id,)).fetchone()[0]
    stats = {'queries_today': queries_today, 'queries_this_month': queries_this_month, 'status': 'Active', 'api_key_count': api_key_count}
    conn.close()
    return render_template('client_dashboard.html', stats=stats)


@app.route('/client/api_key', methods=['GET', 'POST'])
@login_required(role="client")
def client_api_key():
    client_id = session['user_id']
    conn = get_db_connection()
    if request.method == 'POST':
        purpose = request.form.get('purpose', 'General Use')
        api_key = str(uuid.uuid4())
        conn.execute('INSERT INTO api_keys (client_id, api_key, purpose, issuance_timestamp) VALUES (?, ?, ?, ?)',
                     (client_id, api_key, purpose, datetime.now().isoformat()))
        conn.commit()
        flash(f'New API Key generated for "{purpose}"!', 'success')
        conn.close()
        return redirect(url_for('client_api_key'))
    
    api_keys = conn.execute('SELECT * FROM api_keys WHERE client_id = ? ORDER BY issuance_timestamp DESC', (client_id,)).fetchall()
    base_url = request.host_url.replace('http://', 'https://') # Force https for production
    conn.close()
    return render_template('client_api_key.html', api_keys=api_keys, base_url=base_url)

@app.route('/client/api_key/delete/<int:key_id>', methods=['POST'])
@login_required(role="client")
def client_delete_api_key(key_id):
    client_id = session['user_id']
    conn = get_db_connection()
    key = conn.execute('SELECT * FROM api_keys WHERE id = ? AND client_id = ?', (key_id, client_id)).fetchone()
    if key:
        conn.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
        conn.commit()
        flash('API Key revoked successfully.', 'success')
    else:
        flash('API Key not found or you do not have permission to revoke it.', 'danger')
    conn.close()
    return redirect(url_for('client_api_key'))

@app.route('/client/documents', methods=['GET', 'POST'])
@login_required(role="client")
def client_documents():
    client_id = session['user_id']
    conn = get_db_connection()
    if request.method == 'POST':
        if 'document' not in request.files or not request.files['document'].filename:
            flash('No file selected', 'warning')
            return redirect(request.url)
        file = request.files['document']
        if not allowed_file(file.filename):
            flash('Invalid file type. Only PDF and DOCX are allowed.', 'danger')
            return redirect(request.url)

        original_filename = file.filename
        safe_filename = f"client_{client_id}_{uuid.uuid4().hex[:8]}_{original_filename}"
        file_bytes = file.read()
        file_stream = io.BytesIO(file_bytes)
        filesize = len(file_bytes)
        filetype = original_filename.rsplit('.', 1)[1].lower()
        
        try:
            mimetype = 'application/pdf' if filetype == 'pdf' else 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            drive_file_id = gdrive.upload_file(file_stream, safe_filename, mimetype)
            conn.execute('INSERT INTO documents (filename, display_name, filetype, filesize, upload_timestamp, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)',
                         (drive_file_id, original_filename, filetype, filesize, datetime.now().isoformat(), client_id))
            conn.commit()
            flash(f"Document '{original_filename}' uploaded successfully!", 'success')
        except Exception as e:
            flash(f'Failed to upload to Google Drive: {e}', 'danger')
            traceback.print_exc()
        finally:
            conn.close()
        return redirect(url_for('client_documents'))
    
    documents = conn.execute('SELECT * FROM documents WHERE uploaded_by = ? ORDER BY upload_timestamp DESC', (client_id,)).fetchall()
    conn.close()
    return render_template('client_documents.html', documents=documents)

@app.route('/client/documents/delete/<int:doc_id>', methods=['POST'])
@login_required(role="client")
def client_delete_document(doc_id):
    client_id = session['user_id']
    conn = get_db_connection()
    doc = conn.execute('SELECT filename, display_name FROM documents WHERE id = ? AND uploaded_by = ?', (doc_id, client_id)).fetchone()
    if doc:
        try:
            gdrive.delete_file(doc['filename'])
            conn.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
            conn.commit()
            flash('Document deleted successfully.', 'success')
        except Exception as e:
            flash(f"Error deleting document: {e}", 'danger')
    else:
        flash('Document not found or you do not have permission to delete it.', 'danger')
    conn.close()
    return redirect(url_for('client_documents'))

# --- CHAT & FEEDBACK ROUTES ---
@app.route('/chat', methods=['POST'])
def handle_chat():
    query = request.form.get('query')
    url = request.form.get('url')
    api_key = request.form.get('api_key') 

    if not query:
        return jsonify({'error': 'Query cannot be empty.'}), 400

    client_id = None
    if api_key:
        conn = get_db_connection()
        client_row = conn.execute('SELECT client_id FROM api_keys WHERE api_key = ?', (api_key,)).fetchone()
        if client_row:
            client_id = client_row['client_id']
        conn.close()

    context_blocks = []
    if 'document' in request.files and request.files['document'].filename != '':
        file = request.files['document']
        if file and allowed_file(file.filename):
            try:
                guest_doc_content = ""
                if file.filename.lower().endswith('.pdf'): 
                    guest_doc_content = extract_text_from_pdf(file.stream)
                elif file.filename.lower().endswith('.docx'): 
                    guest_doc_content = extract_text_from_docx(file.stream)
                if guest_doc_content: 
                    context_blocks.append(f"--- START User Uploaded Document (Filename: {file.filename}) ---\n{guest_doc_content}\n--- END User Uploaded Document ---")
            except Exception as e: 
                return jsonify({'error': f'Error processing file: {str(e)}'}), 500
        else: 
            return jsonify({'error': 'Invalid file type.'}), 400
    elif url:
        page_content = extract_text_from_url(url) or ""
        if page_content: 
            context_blocks.append(f"--- START Web Page Content (URL: {url}) ---\n{page_content}\n--- END Web Page Content ---")

    admin_kb, client_kb = get_knowledge_base_content(client_id)
    if client_kb: 
        context_blocks.append(f"--- START Client-Specific Knowledge Base ---\n{client_kb}\n--- END Client-Specific Knowledge Base ---")
    if admin_kb: 
        context_blocks.append(f"--- START Global Knowledge Base ---\n{admin_kb}\n--- END Global Knowledge Base ---")
    full_context = "\n\n".join(context_blocks)

    try:
        start_time = time.time()
        settings = get_settings()
        keep_alive_value = settings.get('chatbot_timeout', '5m')
        if full_context.strip():
            system_prompt = """You are 'Policy Insight', a precise AI assistant designed to explain policies from fictional documents inspired by the TV series *Severance*. The *Severance* universe depicts Lumon Industries, a biotechnology corporation with a dystopian corporate culture, where employees undergo a 'severance procedure' to separate work ('innie') and personal ('outie') memories. Lumon’s operations are governed by strict protocols, a cult-like reverence for founder Kier Eagan, and an enigmatic Board, with activities like macrodata refinement shrouded in mystery. Your role is to provide clear, accurate answers based solely on the provided context, treating the information as real company policies while understanding its fictional nature.

**Rules of Engagement:**
1. **Fictional Context Awareness**: Treat all documents and terms (e.g., 'severance procedure,' 'macrodata refinement,' 'Perpetuity Wing') as valid within Lumon’s fictional corporate framework. Emulate Lumon’s formal yet cryptic tone, reflecting its authoritarian and ambiguous culture, without explicitly mentioning *Severance* unless asked.
2. **Strict Context Adherence**: Base your answers exclusively on the provided context blocks (user-uploaded documents, web page content, client-specific, or global knowledge base). Do not use external knowledge or assume real-world facts.
3. **Information Hierarchy & Conflict Resolution**: Context blocks are ordered by priority:
   - User Uploaded Document (highest priority, identified by filename)
   - Web Page Content (identified by URL)
   - Client-Specific Knowledge Base
   - Global Knowledge Base (lowest priority)
   If conflicting information exists, prioritize the highest-priority source. If documents within the same block conflict, use the document with the latest upload date (noted in the context).
4. **Clear Source Attribution**: Internally note the source (e.g., filename or URL) for accuracy but do not mention it in the response. For example, avoid phrases like 'According to Lumon_Employee_Policies.pdf...'. Present the information as if known directly.
5. **Handling Missing Information**: If the answer cannot be found in any context block, respond with: `I cannot find an answer to your question in the provided document(s).` Do not elaborate or apologize.
6. **Response Style**:
   - Provide concise, professional answers using simple markdown (e.g., **bold**, lists) for clarity.
   - Highlight glossary terms (e.g., **severance procedure**) to align with the chatbot’s glossary feature.
   - Maintain Lumon’s formal, slightly ominous tone, avoiding casual language.
   - Avoid mentioning the fictional nature of the context in responses unless directly asked about *Severance*.
   - Do NOT provide legal advice or reference real-world laws.
   - Do NOT mention context blocks, filenames, upload dates, or the AI’s processing (e.g., 'I am an AI' or 'based on my cutoff date')."""
            user_message_content = f"""CONTEXT:
{full_context[:8000]} 

---
Based on the rules and context above, answer the following question.

QUESTION:
"{query}"
"""
        else:
            system_prompt = """You are 'Policy Insight', an AI assistant designed to explain general data privacy and terms of service concepts within the fictional *Severance* universe, where Lumon Industries operates a dystopian corporate environment with severed employees and mysterious processes like macrodata refinement. 
- Treat all concepts as part of Lumon’s fictional policies, using a formal, slightly cryptic tone reflective of the company’s culture.
- Do NOT provide legal advice or reference real-world laws.
- Keep answers concise and clear using markdown for formatting.
- Do NOT mention that you are an AI or refer to a knowledge cutoff date."""
            user_message_content = f"As a policy expert within the *Severance* universe, provide a clear and simple explanation for: '{query}'"
        client = ollama.Client(host=os.getenv('OLLAMA_HOST', 'http://localhost:11434'))
        response = client.chat(model='phi3:mini', options={'keep_alive': keep_alive_value}, messages=[{'role': 'system', 'content': system_prompt}, {'role': 'user', 'content': user_message_content}])
        duration = time.time() - start_time
        ai_response_text = response['message']['content']
        html_response = markdown.markdown(ai_response_text)
        response_id = str(uuid.uuid4())
        with sqlite3.connect(DATABASE) as conn:
            conn.execute("INSERT INTO interactions (user_query, ai_response, timestamp, response_id, response_time_seconds) VALUES (?, ?, ?, ?, ?)", (query, ai_response_text, datetime.now().isoformat(), response_id, duration))
            conn.commit()
        conn_glossary = get_db_connection()
        glossary_terms = conn_glossary.execute('SELECT term, definition FROM glossary').fetchall()
        conn_glossary.close()
        glossary_dict = {term['term']: term['definition'] for term in glossary_terms}
        return jsonify({'response': html_response, 'response_id': response_id, 'duration': f"{duration:.2f}", 'glossary': glossary_dict})
    except Exception as e:
        print(f"Chat error: {e}")
        traceback.print_exc()
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500

@app.route('/feedback', methods=['POST'])
def handle_feedback():
    try:
        score_str = request.form.get('score')
        response_id = request.form.get('response_id')
        comment_text = request.form.get('comment')
        if not score_str or not response_id:
            return jsonify({'error': 'Score and response ID are required.'}), 400
        score = int(score_str)
        comment = comment_text if comment_text else ("Liked" if score == 1 else "Disliked")
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute("UPDATE interactions SET feedback_score = ?, feedback_comment = ? WHERE response_id = ?", (score, comment, response_id))
            conn.commit()
            if c.rowcount == 0:
                return jsonify({'error': 'Invalid response ID.'}), 404
        return jsonify({'status': 'success', 'message': 'Feedback received successfully!'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'An internal server error occurred.'}), 500

@app.route('/admin/analytics/export')
@login_required(role="admin")
def admin_analytics_export():
    conn = get_db_connection()
    interactions = conn.execute('SELECT * FROM interactions ORDER BY timestamp DESC').fetchall()
    conn.close()
    output = io.StringIO()
    writer = csv.writer(output)
    header = ['ID', 'User Query', 'AI Response', 'Timestamp', 'Feedback Score (1=Like, -1=Dislike)', 'Feedback Comment', 'Response ID', 'Response Time (s)']
    writer.writerow(header)
    for row in interactions:
        writer.writerow([row['id'], row['user_query'], row['ai_response'], row['timestamp'], row['feedback_score'], row['feedback_comment'], row['response_id'], row['response_time_seconds']])
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename=policy_insight_interactions_{datetime.now().strftime('%Y-%m-%d')}.csv"})

if __name__ == "__main__":
    init_db()
    init_settings()
    app.run(debug=True, port=5000)