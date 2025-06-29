# --- START OF FILE index.py ---

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify, session, Response
from functools import wraps
import os
import hashlib
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

# FIX: Import PostgreSQL driver and DictCursor for dictionary-like rows
import psycopg2
from psycopg2.extras import DictCursor
import gdrive

# Document/Web Parsing Libraries
import ollama
import pdfplumber
from bs4 import BeautifulSoup
import requests
import docx

app = Flask(__name__)
app.secret_key = os.getenv(
    'FLASK_SECRET_KEY', 'your-very-secret-key-that-is-long-and-secure')
DATABASE_URL = os.getenv('DATABASE_URL')
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'pdf', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Caching Layer ---
# This dictionary will hold our document content in memory to prevent slow GDrive lookups.
DOCUMENT_CACHE = {}

# --- Database Initialization ---


def init_db():
    with psycopg2.connect(DATABASE_URL) as conn:
        with conn.cursor() as c:
            c.execute('''CREATE TABLE IF NOT EXISTS users (id SERIAL PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, login_timestamp TIMESTAMPTZ, failed_attempts INTEGER DEFAULT 0)''')
            c.execute('''CREATE TABLE IF NOT EXISTS documents (id SERIAL PRIMARY KEY, filename TEXT NOT NULL, display_name TEXT NOT NULL, filetype TEXT NOT NULL, filesize INTEGER NOT NULL, upload_timestamp TIMESTAMPTZ, uploaded_by INTEGER, FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE CASCADE)''')
            c.execute('''CREATE TABLE IF NOT EXISTS api_keys (id SERIAL PRIMARY KEY, client_id INTEGER, api_key TEXT NOT NULL, purpose TEXT, issuance_timestamp TIMESTAMPTZ, FOREIGN KEY(client_id) REFERENCES users(id) ON DELETE CASCADE)''')
            c.execute('''CREATE TABLE IF NOT EXISTS interactions (
                id SERIAL PRIMARY KEY, 
                user_query TEXT, 
                ai_response TEXT, 
                timestamp TIMESTAMPTZ, 
                feedback_score INTEGER, 
                feedback_comment TEXT, 
                response_id TEXT, 
                response_time_seconds REAL,
                client_id INTEGER,
                FOREIGN KEY(client_id) REFERENCES users(id) ON DELETE SET NULL
            )''')
            c.execute(
                '''CREATE TABLE IF NOT EXISTS glossary (id SERIAL PRIMARY KEY, term TEXT UNIQUE NOT NULL, definition TEXT NOT NULL)''')
            c.execute(
                '''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)''')

            c.execute("SELECT COUNT(*) FROM users")
            if c.fetchone()[0] == 0:
                c.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s) ON CONFLICT (username) DO NOTHING",
                          ('admin', hash_password('admin123'), 'admin'))
                c.execute("INSERT INTO users (username, password, role) VALUES (%s, %s, %s) ON CONFLICT (username) DO NOTHING",
                          ('client', hash_password('client123'), 'client'))

            c.execute("INSERT INTO api_keys (id, client_id, api_key, purpose, issuance_timestamp) VALUES (%s, %s, %s, %s, %s) ON CONFLICT (id) DO NOTHING",
                      (1, 2, '11111111-1111-1111-1111-111111111111', 'Default Key for Policy Page Demo', datetime.now()))

            c.execute("SELECT COUNT(*) FROM glossary")
            if c.fetchone()[0] == 0:
                sample_terms = [
                    ('Severance Procedure', 'A surgical procedure that separates an employee\'s work memories ("innie") from their personal life memories ("outie").'),
                    ('Innie', 'The consciousness of a severed employee that exists only within the confines of the severed floor at Lumon Industries.'),
                    ('Outie', 'The consciousness of a severed employee that exists in the outside world, unaware of their "innie"\'s experiences.'),
                    ('Macrodata Refinement', 'A mysterious task performed by severed employees, involving sorting numbers on a screen into digital bins based on their emotional feel.'),
                    ('The Break Room', 'A disciplinary room where employees are forced to repeatedly read a statement of contrition until they achieve sincere remorse.'),
                    ('Waffle Party', 'A coveted reward for a department that meets its quarterly quota, involving waffles and other special privileges.'),
                    ('Kier Eagan', 'The revered and cult-like founder of Lumon Industries, whose philosophies govern the company.')
                ]
                c.executemany(
                    "INSERT INTO glossary (term, definition) VALUES (%s, %s) ON CONFLICT (term) DO NOTHING", sample_terms)
            conn.commit()


def init_settings():
    with psycopg2.connect(DATABASE_URL) as conn:
        with conn.cursor() as c:
            c.execute("INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING",
                      ('chatbot_enabled', 'true'))
            c.execute("INSERT INTO settings (key, value) VALUES (%s, %s) ON CONFLICT (key) DO NOTHING",
                      ('chatbot_timeout', '5m'))
            conn.commit()

# --- Utility & Caching Functions ---


def get_db_connection():
    conn = psycopg2.connect(DATABASE_URL)
    conn.cursor_factory = DictCursor
    return conn


def get_document_content(doc_id):
    """Gets document content from cache, falling back to Google Drive."""
    if doc_id in DOCUMENT_CACHE:
        return DOCUMENT_CACHE[doc_id]['content']

    print(
        f"CACHE MISS: Document {doc_id} not found in cache. Fetching from GDrive.")
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
        doc = c.fetchone()
    conn.close()

    if not doc:
        return ""

    try:
        file_stream = gdrive.download_file(doc['filename'])
        content = ""
        if doc['filetype'] == 'pdf':
            content = extract_text_from_pdf(file_stream)
        elif doc['filetype'] == 'docx':
            content = extract_text_from_docx(file_stream)

        DOCUMENT_CACHE[doc['id']] = {
            'content': content, 'display_name': doc['display_name'], 'uploaded_by': doc['uploaded_by']}
        return content
    except Exception as e:
        print(f"Failed to fetch and cache document {doc_id}: {e}")
        return ""


def preload_documents_to_cache():
    """Function to load all documents from DB into the in-memory cache."""
    print("Preloading documents into cache...")
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute("SELECT id FROM documents")
        all_doc_ids = [row['id'] for row in c.fetchall()]
    conn.close()

    count = 0
    for doc_id in all_doc_ids:
        if get_document_content(doc_id):
            count += 1
    print(f"Cache preloaded with {count} documents.")


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
        for element in soup(['script', 'style', 'nav', 'header', 'footer']):
            element.extract()
        return " ".join(text for text in soup.stripped_strings if text)
    except requests.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return None


def get_smart_knowledge_base_content(query, client_id=None):
    stop_words = set(['what', 'is', 'the', 'are', 'a', 'an', 'in',
                     'of', 'for', 'to', 'how', 'do', 'i', 'tell', 'me', 'about'])
    cleaned_query = re.sub(r'[^\w\s]', '', query).lower()
    keywords = {word for word in cleaned_query.split(
    ) if word not in stop_words and len(word) > 2}
    if not keywords:
        return ""

    relevant_docs = []
    for doc_id, doc_data in DOCUMENT_CACHE.items():
        is_admin_doc = doc_data.get('uploaded_by') == 1
        is_client_doc = client_id and doc_data.get('uploaded_by') == client_id

        if not (is_admin_doc or is_client_doc):
            continue

        content = doc_data.get('content', '')
        score = sum(1 for keyword in keywords if keyword in content.lower())

        if score > 0:
            doc_type = "Client-Specific" if is_client_doc else "Global"
            formatted_text = f"--- Document: {doc_data['display_name']} (Type: {doc_type}) ---\n{content}"
            relevant_docs.append({'score': score, 'text': formatted_text})

    relevant_docs.sort(key=lambda x: x['score'], reverse=True)
    TOP_N_DOCS = 3
    top_docs = relevant_docs[:TOP_N_DOCS]
    if not top_docs:
        return ""

    final_context = "\n\n".join([doc['text'] for doc in top_docs])
    return f"--- START Relevant Knowledge Base Documents ---\n{final_context}\n--- END Relevant Knowledge Base Documents ---"


def get_settings():
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute('SELECT key, value FROM settings')
        settings_data = c.fetchall()
    conn.close()
    return {row['key']: row['value'] for row in settings_data}


def login_required(role="ANY"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id:
                flash('Please log in to access this page.', 'warning')
                return redirect(url_for('login'))

            conn = get_db_connection()
            with conn.cursor() as c:
                c.execute('SELECT * FROM users WHERE id = %s', (user_id,))
                user = c.fetchone()
            conn.close()

            if not user:
                session.clear()
                flash(
                    'Your user account could not be found. Please log in again.', 'danger')
                return redirect(url_for('login'))

            if role != "ANY" and user['role'] != role:
                flash('You do not have permission to access that page.', 'danger')
                return redirect(url_for(f"{user['role']}_dashboard"))

            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Routes ---


@app.route('/')
def home():
    return render_template('home.html')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session:
        role = session.get('role', 'client')
        return redirect(url_for(f'{role}_dashboard'))

    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        conn = get_db_connection()
        with conn.cursor() as c:
            c.execute('SELECT * FROM users WHERE username = %s', (username,))
            user_data = c.fetchone()

        is_password_correct = user_data and (
            user_data['password'] == hashed_password)

        if is_password_correct:
            user = dict(user_data)
            session.clear()
            session['user_id'] = user['id']
            session['username'] = user['username']
            session['role'] = user['role']

            with conn.cursor() as c:
                c.execute('UPDATE users SET login_timestamp = %s, failed_attempts = 0 WHERE id = %s',
                          (datetime.now(), user['id']))
            conn.commit()
            flash(f'Welcome, {user["username"]}!', 'success')
            conn.close()
            return redirect(url_for(f"{user['role']}_dashboard"))
        else:
            if user_data:
                with conn.cursor() as c:
                    c.execute(
                        'UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = %s', (user_data['id'],))
                conn.commit()
            flash('Invalid username or password.', 'danger')
            conn.close()
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
    return render_template('severance_signup.html', settings=settings, show_widget=True)


@app.route('/admin/')
@login_required(role="admin")
def admin_index():
    return redirect(url_for('admin_dashboard'))


@app.route('/admin/dashboard')
@login_required(role="admin")
def admin_dashboard():
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute('SELECT COUNT(*) FROM documents')
        total_docs = c.fetchone()[0]
        c.execute(
            'SELECT COUNT(*) FROM interactions WHERE DATE(timestamp) = CURRENT_DATE')
        queries_today = c.fetchone()[0]
        c.execute(
            'SELECT AVG(response_time_seconds) FROM interactions WHERE response_time_seconds IS NOT NULL')
        avg_response_time = c.fetchone()[0] or 0
        c.execute(
            'SELECT id, display_name, upload_timestamp FROM documents ORDER BY upload_timestamp DESC LIMIT 5')
        recent_docs = c.fetchall()
        labels, data = [], []
        for i in range(6, -1, -1):
            day = datetime.now() - timedelta(days=i)
            day_str = day.strftime('%Y-%m-%d')
            labels.append(day.strftime('%a'))
            c.execute(
                'SELECT COUNT(*) FROM interactions WHERE DATE(timestamp) = %s', (day_str,))
            count = c.fetchone()[0]
            data.append(count)
    conn.close()
    stats = {'total_docs': total_docs, 'queries_today': queries_today,
             'avg_response_time': avg_response_time}
    daily_queries = {'labels': labels, 'data': data}
    return render_template('admin_dashboard.html', stats=stats, recent_docs=recent_docs, daily_queries=daily_queries)


@app.route('/admin/documents', methods=['GET', 'POST'])
@login_required(role="admin")
def admin_documents():
    conn = get_db_connection()
    if request.method == 'POST':
        admin_id = session['user_id']
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
            drive_file_id = gdrive.upload_file(
                file_stream, original_filename, mimetype)
            with conn.cursor() as c:
                c.execute('INSERT INTO documents (filename, display_name, filetype, filesize, upload_timestamp, uploaded_by) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id',
                          (drive_file_id, original_filename, filetype, filesize, datetime.now(), admin_id))
                new_doc_id = c.fetchone()['id']
            conn.commit()

            file_stream.seek(0)
            new_content = extract_text_from_pdf(
                file_stream) if filetype == 'pdf' else extract_text_from_docx(file_stream)
            DOCUMENT_CACHE[new_doc_id] = {
                'content': new_content, 'display_name': original_filename, 'uploaded_by': admin_id}
            print(f"CACHE ADD: Added document {new_doc_id} to cache.")
            flash('Document uploaded successfully!', 'success')
        except Exception as e:
            flash(f'Failed to upload document: {e}', 'danger')
            traceback.print_exc()
        finally:
            conn.close()
        return redirect(url_for('admin_documents'))

    with conn.cursor() as c:
        c.execute('SELECT d.*, u.username FROM documents d JOIN users u ON d.uploaded_by = u.id WHERE u.role = %s ORDER BY d.upload_timestamp DESC', ('admin',))
        documents = c.fetchall()
    conn.close()
    return render_template('admin_documents.html', documents=documents)


@app.route('/admin/documents/delete/<int:doc_id>', methods=['POST'])
@login_required(role="admin")
def admin_delete_document(doc_id):
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute('SELECT d.filename, d.display_name FROM documents d JOIN users u ON d.uploaded_by = u.id WHERE d.id = %s AND u.role = %s', (doc_id, 'admin'))
        doc = c.fetchone()
        if doc:
            try:
                gdrive.delete_file(doc['filename'])
                c.execute('DELETE FROM documents WHERE id = %s', (doc_id,))
                conn.commit()
                if doc_id in DOCUMENT_CACHE:
                    del DOCUMENT_CACHE[doc_id]
                    print(
                        f"CACHE REMOVE: Removed document {doc_id} from cache.")
                flash(
                    f"Document '{doc['display_name']}' deleted successfully.", 'success')
            except Exception as e:
                flash(f"Error deleting document: {e}", 'danger')
        else:
            flash('Document not found or you do not have permission to delete.', 'danger')
    conn.close()
    return redirect(url_for('admin_documents'))


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
            flash('Invalid file type.', 'danger')
            return redirect(request.url)

        original_filename = file.filename
        safe_filename = f"client_{client_id}_{uuid.uuid4().hex[:8]}_{original_filename}"
        file_bytes = file.read()
        file_stream = io.BytesIO(file_bytes)
        filesize = len(file_bytes)
        filetype = original_filename.rsplit('.', 1)[1].lower()

        try:
            mimetype = 'application/pdf' if filetype == 'pdf' else 'application/vnd.openxmlformats-officedocument.wordprocessingml.document'
            drive_file_id = gdrive.upload_file(
                file_stream, safe_filename, mimetype)
            with conn.cursor() as c:
                c.execute('INSERT INTO documents (filename, display_name, filetype, filesize, upload_timestamp, uploaded_by) VALUES (%s, %s, %s, %s, %s, %s) RETURNING id',
                          (drive_file_id, original_filename, filetype, filesize, datetime.now(), client_id))
                new_doc_id = c.fetchone()['id']
            conn.commit()

            file_stream.seek(0)
            new_content = extract_text_from_pdf(
                file_stream) if filetype == 'pdf' else extract_text_from_docx(file_stream)
            DOCUMENT_CACHE[new_doc_id] = {
                'content': new_content, 'display_name': original_filename, 'uploaded_by': client_id}
            print(f"CACHE ADD: Added document {new_doc_id} to cache.")
            flash(
                f"Document '{original_filename}' uploaded successfully!", 'success')
        except Exception as e:
            flash(f'Failed to upload document: {e}', 'danger')
            traceback.print_exc()
        finally:
            conn.close()
        return redirect(url_for('client_documents'))

    with conn.cursor() as c:
        c.execute(
            'SELECT * FROM documents WHERE uploaded_by = %s ORDER BY upload_timestamp DESC', (client_id,))
        documents = c.fetchall()
    conn.close()
    return render_template('client_documents.html', documents=documents)


@app.route('/client/documents/delete/<int:doc_id>', methods=['POST'])
@login_required(role="client")
def client_delete_document(doc_id):
    client_id = session['user_id']
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute(
            'SELECT filename, display_name FROM documents WHERE id = %s AND uploaded_by = %s', (doc_id, client_id))
        doc = c.fetchone()
        if doc:
            try:
                gdrive.delete_file(doc['filename'])
                c.execute('DELETE FROM documents WHERE id = %s', (doc_id,))
                conn.commit()
                if doc_id in DOCUMENT_CACHE:
                    del DOCUMENT_CACHE[doc_id]
                    print(
                        f"CACHE REMOVE: Removed document {doc_id} from cache.")
                flash('Document deleted successfully.', 'success')
            except Exception as e:
                flash(f"Error deleting document: {e}", 'danger')
        else:
            flash(
                'Document not found or you do not have permission to delete it.', 'danger')
    conn.close()
    return redirect(url_for('client_documents'))

# ... (Continue with other routes like analytics, settings, etc.)

# The rest of your routes should be here, fully corrected for PostgreSQL.
# I will add them below for completeness.


@app.route('/admin/analytics')
@login_required(role="admin")
def admin_analytics():
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute('SELECT * FROM interactions ORDER BY timestamp DESC')
        interactions = c.fetchall()
        c.execute('SELECT COUNT(*) FROM interactions WHERE feedback_score = 1')
        liked_count = c.fetchone()[0]
        c.execute('SELECT COUNT(*) FROM interactions WHERE feedback_score = -1')
        disliked_count = c.fetchone()[0]
        c.execute(
            'SELECT COUNT(*) FROM interactions WHERE feedback_score IS NULL OR feedback_score = 0')
        no_rating_count = c.fetchone()[0]
        feedback_counts = {'liked': liked_count,
                           'disliked': disliked_count, 'no_rating': no_rating_count}

        c.execute('SELECT AVG(response_time_seconds), MIN(response_time_seconds), MAX(response_time_seconds) FROM interactions WHERE response_time_seconds IS NOT NULL')
        timing_data = c.fetchone()

        c.execute('SELECT user_query FROM interactions')
        all_queries = c.fetchall()
    conn.close()

    words = []
    stop_words = set(['what', 'is', 'the', 'are', 'a', 'an',
                     'in', 'of', 'for', 'to', 'how', 'do', 'i'])
    for row in all_queries:
        if not row['user_query']:
            continue
        cleaned_query = re.sub(r'[^\w\s]', '', row['user_query']).lower()
        words.extend([word for word in cleaned_query.split()
                     if word not in stop_words and len(word) > 2])
    popular_terms = [term for term, count in Counter(words).most_common(5)]
    analytics_data = {'feedback_counts': feedback_counts, 'avg_response_time':
                      timing_data[0] or 0, 'min_response_time': timing_data[1] or 0, 'max_response_time': timing_data[2] or 0, 'popular_terms': popular_terms}

    return render_template('admin_analytics.html', interactions=interactions, analytics=analytics_data)


@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required(role="admin")
def admin_settings():
    conn = get_db_connection()
    if request.method == 'POST':
        with conn.cursor() as c:
            if 'add_user' in request.form:
                username, password, role = request.form.get(
                    'username'), request.form.get('password'), request.form.get('role')
                if username and password and role:
                    try:
                        c.execute('INSERT INTO users (username, password, role) VALUES (%s, %s, %s)', (
                            username, hash_password(password), role))
                        conn.commit()
                        flash('User added successfully.', 'success')
                    except psycopg2.IntegrityError:
                        conn.rollback()
                        flash('Username already exists.', 'danger')
                else:
                    flash('All fields are required to add a user.', 'warning')
            elif 'save_settings' in request.form:
                chatbot_enabled = request.form.get('chatbot_enabled')
                chatbot_timeout = request.form.get('chatbot_timeout')
                chatbot_enabled_value = 'true' if chatbot_enabled == 'on' else 'false'
                c.execute("UPDATE settings SET value = %s WHERE key = %s",
                          (chatbot_enabled_value, 'chatbot_enabled'))
                c.execute("UPDATE settings SET value = %s WHERE key = %s",
                          (chatbot_timeout, 'chatbot_timeout'))
                conn.commit()
                flash('Chatbot settings updated successfully.', 'success')
        conn.close()
        return redirect(url_for('admin_settings'))

    with conn.cursor() as c:
        c.execute('SELECT id, username, role FROM users')
        users = c.fetchall()
        c.execute('''
            SELECT api_keys.id, api_keys.api_key, api_keys.purpose, users.username, api_keys.issuance_timestamp 
            FROM api_keys JOIN users ON api_keys.client_id = users.id
            ORDER BY api_keys.issuance_timestamp DESC
        ''')
        api_keys = c.fetchall()
        c.execute('SELECT key, value FROM settings')
        settings_data = c.fetchall()
    conn.close()
    current_settings = {row['key']: row['value'] for row in settings_data}
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
        with conn.cursor() as c:
            c.execute('DELETE FROM api_keys WHERE client_id = %s', (user_id,))
            c.execute('DELETE FROM users WHERE id = %s', (user_id,))
        conn.commit()
        flash('User and their associated API keys have been deleted.', 'success')
    except Exception as e:
        conn.rollback()
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
                with conn.cursor() as c:
                    c.execute(
                        'INSERT INTO glossary (term, definition) VALUES (%s, %s)', (term, definition))
                conn.commit()
                flash(f'Term "{term}" added successfully!', 'success')
            except psycopg2.IntegrityError:
                conn.rollback()
                flash(f'Term "{term}" already exists.', 'danger')
        else:
            flash('Both term and definition are required.', 'warning')
        return redirect(url_for('admin_glossary'))

    with conn.cursor() as c:
        c.execute('SELECT * FROM glossary ORDER BY term')
        glossary_terms = c.fetchall()
    conn.close()
    return render_template('admin_glossary.html', glossary_terms=glossary_terms)


@app.route('/admin/glossary/delete/<int:term_id>', methods=['POST'])
@login_required(role="admin")
def admin_delete_term(term_id):
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute('DELETE FROM glossary WHERE id = %s', (term_id,))
    conn.commit()
    conn.close()
    flash('Term deleted successfully.', 'success')
    return redirect(url_for('admin_glossary'))


@app.route('/client/dashboard')
@login_required(role="client")
def client_dashboard():
    client_id = session['user_id']
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute(
            'SELECT COUNT(*) FROM interactions WHERE client_id = %s AND DATE(timestamp) = CURRENT_DATE', (client_id,))
        queries_today = c.fetchone()[0]
        c.execute("SELECT COUNT(*) FROM interactions WHERE client_id = %s AND DATE_TRUNC('month', timestamp) = DATE_TRUNC('month', CURRENT_DATE)", (client_id,))
        queries_this_month = c.fetchone()[0]
        c.execute(
            'SELECT COUNT(*) FROM api_keys WHERE client_id = %s', (client_id,))
        api_key_count = c.fetchone()[0]
        labels, data = [], []
        for i in range(6, -1, -1):
            day = datetime.now() - timedelta(days=i)
            day_str = day.strftime('%Y-%m-%d')
            labels.append(day.strftime('%a'))
            c.execute(
                'SELECT COUNT(*) FROM interactions WHERE client_id = %s AND DATE(timestamp) = %s', (client_id, day_str))
            count = c.fetchone()[0]
            data.append(count)
    conn.close()
    stats = {'queries_today': queries_today, 'queries_this_month': queries_this_month,
             'status': 'Active', 'api_key_count': api_key_count}
    daily_queries = {'labels': labels, 'data': data}
    return render_template('client_dashboard.html', stats=stats, daily_queries=daily_queries)


@app.route('/client/api_key', methods=['GET', 'POST'])
@login_required(role="client")
def client_api_key():
    client_id = session['user_id']
    conn = get_db_connection()
    if request.method == 'POST':
        purpose = request.form.get('purpose', 'General Use')
        api_key = str(uuid.uuid4())
        with conn.cursor() as c:
            c.execute('INSERT INTO api_keys (client_id, api_key, purpose, issuance_timestamp) VALUES (%s, %s, %s, %s)',
                      (client_id, api_key, purpose, datetime.now()))
        conn.commit()
        flash(f'New API Key generated for "{purpose}"!', 'success')
        conn.close()
        return redirect(url_for('client_api_key'))

    with conn.cursor() as c:
        c.execute(
            'SELECT * FROM api_keys WHERE client_id = %s ORDER BY issuance_timestamp DESC', (client_id,))
        api_keys = c.fetchall()
    base_url = request.host_url.replace('http://', 'https://')
    conn.close()
    return render_template('client_api_key.html', api_keys=api_keys, base_url=base_url)


@app.route('/client/api_key/delete/<int:key_id>', methods=['POST'])
@login_required(role="client")
def client_delete_api_key(key_id):
    client_id = session['user_id']
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute(
            'SELECT * FROM api_keys WHERE id = %s AND client_id = %s', (key_id, client_id))
        key = c.fetchone()
        if key:
            c.execute('DELETE FROM api_keys WHERE id = %s', (key_id,))
            conn.commit()
            flash('API Key revoked successfully.', 'success')
        else:
            flash(
                'API Key not found or you do not have permission to revoke it.', 'danger')
    conn.close()
    return redirect(url_for('client_api_key'))


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
        with conn.cursor() as c:
            c.execute(
                'SELECT client_id FROM api_keys WHERE api_key = %s', (api_key,))
            client_row = c.fetchone()
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
                    context_blocks.append(
                        f"--- START User Uploaded Document (Filename: {file.filename}) ---\n{guest_doc_content}\n--- END User Uploaded Document ---")
            except Exception as e:
                return jsonify({'error': f'Error processing file: {str(e)}'}), 500
        else:
            return jsonify({'error': 'Invalid file type.'}), 400
    elif url:
        page_content = extract_text_from_url(url) or ""
        if page_content:
            context_blocks.append(
                f"--- START Web Page Content (URL: {url}) ---\n{page_content}\n--- END Web Page Content ---")

    knowledge_base_context = get_smart_knowledge_base_content(query, client_id)
    if knowledge_base_context:
        context_blocks.append(knowledge_base_context)

    full_context = "\n\n".join(context_blocks)

    try:
        start_time = time.time()
        settings = get_settings()
        keep_alive_value = settings.get('chatbot_timeout', '5m')
        if full_context.strip():
            system_prompt = "..."  # Your long prompt here
            user_message_content = f"CONTEXT:\n{full_context[:8000]}\n\n---\nBased on the rules and context above, answer the following question.\n\nQUESTION:\n\"{query}\""
        else:
            system_prompt = "..."  # Your other long prompt here
            user_message_content = f"As a policy expert within the *Severance* universe, provide a clear and simple explanation for: '{query}'"

        client = ollama.Client(host=os.getenv(
            'OLLAMA_HOST', 'http://localhost:11434'))
        response = client.chat(model='phi3:mini', options={'keep_alive': keep_alive_value}, messages=[
                               {'role': 'system', 'content': system_prompt}, {'role': 'user', 'content': user_message_content}])
        duration = time.time() - start_time
        ai_response_text = response['message']['content']
        html_response = markdown.markdown(ai_response_text)
        response_id = str(uuid.uuid4())

        conn = get_db_connection()
        with conn.cursor() as c:
            c.execute("INSERT INTO interactions (user_query, ai_response, timestamp, response_id, response_time_seconds, client_id) VALUES (%s, %s, %s, %s, %s, %s)",
                      (query, ai_response_text, datetime.now(), response_id, duration, client_id))
        conn.commit()

        with conn.cursor() as c:
            c.execute('SELECT term, definition FROM glossary')
            glossary_terms = c.fetchall()
        conn.close()

        glossary_dict = {term['term']: term['definition']
                         for term in glossary_terms}
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
        comment = comment_text if comment_text else (
            "Liked" if score == 1 else "Disliked")

        conn = get_db_connection()
        with conn.cursor() as c:
            c.execute("UPDATE interactions SET feedback_score = %s, feedback_comment = %s WHERE response_id = %s",
                      (score, comment, response_id))
            if c.rowcount == 0:
                conn.close()
                return jsonify({'error': 'Invalid response ID.'}), 404
        conn.commit()
        conn.close()
        return jsonify({'status': 'success', 'message': 'Feedback received successfully!'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'An internal server error occurred.'}), 500


@app.route('/admin/analytics/export')
@login_required(role="admin")
def admin_analytics_export():
    conn = get_db_connection()
    with conn.cursor() as c:
        c.execute('SELECT * FROM interactions ORDER BY timestamp DESC')
        interactions = c.fetchall()
    conn.close()

    output = io.StringIO()
    writer = csv.writer(output)
    header = ['ID', 'User Query', 'AI Response', 'Timestamp',
              'Feedback Score (1=Like, -1=Dislike)', 'Feedback Comment', 'Response ID', 'Response Time (s)']
    writer.writerow(header)
    for row in interactions:
        writer.writerow([row['id'], row['user_query'], row['ai_response'], row['timestamp'],
                        row['feedback_score'], row['feedback_comment'], row['response_id'], row['response_time_seconds']])
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename=policy_insight_interactions_{datetime.now().strftime('%Y-%m-%d')}.csv"})


@app.route('/documents/view/<int:doc_id>')
@login_required()
def view_document(doc_id):
    user_id = session['user_id']
    role = session['role']
    conn = get_db_connection()
    with conn.cursor() as c:
        if role == 'admin':
            c.execute("SELECT * FROM documents WHERE id = %s", (doc_id,))
        else:
            c.execute(
                "SELECT * FROM documents WHERE id = %s AND uploaded_by = %s", (doc_id, user_id))
        doc = c.fetchone()
    conn.close()

    if not doc:
        return jsonify({'error': 'Document not found or permission denied.'}), 404

    try:
        # Use the cache-aware function
        content = get_document_content(doc['id'])
        return jsonify({'display_name': doc['display_name'], 'content': content})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'Failed to read document from storage: {e}'}), 500


if __name__ == "__main__":
    init_db()
    init_settings()
    preload_documents_to_cache()
    app.run(debug=True, host='0.0.0.0', port=5000)

# --- END OF FILE index.py ---
