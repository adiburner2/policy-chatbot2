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
import sqlite3 # Reverted to SQLite

# Document/Web Parsing Libraries
import ollama
import pdfplumber
from bs4 import BeautifulSoup
import requests
import docx

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-very-secret-key-that-is-long-and-secure')
DATABASE = 'policy_chatbot.db' # Using local SQLite database file
UPLOAD_FOLDER = 'temp_uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'pdf', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Database Initialization ---
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY AUTOINCREMENT, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, login_timestamp DATETIME, failed_attempts INTEGER DEFAULT 0)''')
        # FIX: Added a 'content' column to store the document text directly. 'filename' is now for the original filename.
        c.execute('''CREATE TABLE IF NOT EXISTS documents (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, 
                        filename TEXT NOT NULL, 
                        display_name TEXT NOT NULL, 
                        filetype TEXT NOT NULL, 
                        filesize INTEGER NOT NULL, 
                        upload_timestamp DATETIME, 
                        uploaded_by INTEGER, 
                        content TEXT NOT NULL,
                        FOREIGN KEY(uploaded_by) REFERENCES users(id) ON DELETE CASCADE
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY AUTOINCREMENT, client_id INTEGER, api_key TEXT NOT NULL, purpose TEXT, issuance_timestamp DATETIME, FOREIGN KEY(client_id) REFERENCES users(id) ON DELETE CASCADE)''')
        c.execute('''CREATE TABLE IF NOT EXISTS interactions (
                        id INTEGER PRIMARY KEY AUTOINCREMENT, user_query TEXT, ai_response TEXT, timestamp DATETIME, 
                        feedback_score INTEGER, feedback_comment TEXT, response_id TEXT, response_time_seconds REAL,
                        client_id INTEGER, FOREIGN KEY(client_id) REFERENCES users(id) ON DELETE SET NULL
                     )''')
        c.execute('''CREATE TABLE IF NOT EXISTS glossary (id INTEGER PRIMARY KEY AUTOINCREMENT, term TEXT UNIQUE NOT NULL, definition TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)''')

        if c.execute("SELECT COUNT(*) FROM users").fetchone()[0] == 0:
            c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', hash_password('admin123'), 'admin'))
            c.execute("INSERT OR IGNORE INTO users (username, password, role) VALUES (?, ?, ?)", ('client', hash_password('client123'), 'client'))

        c.execute("INSERT OR IGNORE INTO api_keys (id, client_id, api_key, purpose, issuance_timestamp) VALUES (?, ?, ?, ?, ?)", (1, 2, '11111111-1111-1111-1111-111111111111', 'Default Key for Policy Page Demo', datetime.now()))

        if c.execute("SELECT COUNT(*) FROM glossary").fetchone()[0] == 0:
            sample_terms = [
                ('Severance Procedure', 'A surgical procedure that separates an employee\'s work memories ("innie") from their personal life memories ("outie").'),
                ('Innie', 'The consciousness of a severed employee that exists only within the confines of the severed floor at Lumon Industries.'),
                ('Outie', 'The consciousness of a severed employee that exists in the outside world, unaware of their "innie"\'s experiences.'),
                ('Macrodata Refinement', 'A mysterious task performed by severed employees, involving sorting numbers on a screen into digital bins based on their emotional feel.'),
                ('The Break Room', 'A disciplinary room where employees are forced to repeatedly read a statement of contrition until they achieve sincere remorse.'),
                ('Waffle Party', 'A coveted reward for a department that meets its quarterly quota, involving waffles and other special privileges.'),
                ('Kier Eagan', 'The revered and cult-like founder of Lumon Industries, whose philosophies govern the company.')
            ]
            c.executemany("INSERT OR IGNORE INTO glossary (term, definition) VALUES (?, ?)", sample_terms)
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

def get_smart_knowledge_base_content(query, client_id=None):
    """Finds relevant document content from the SQLite database using keyword matching."""
    stop_words = set(['what', 'is', 'the', 'are', 'a', 'an', 'in', 'of', 'for', 'to', 'how', 'do', 'i', 'tell', 'me', 'about'])
    cleaned_query = re.sub(r'[^\w\s]', '', query).lower()
    keywords = {word for word in cleaned_query.split() if word not in stop_words and len(word) > 2}
    if not keywords: return ""

    conn = get_db_connection()
    # Get all documents accessible to this user (their own + global admin docs)
    query_str = "SELECT id, display_name, content, uploaded_by FROM documents WHERE uploaded_by = 1"
    params = ()
    if client_id:
        query_str += " OR uploaded_by = ?"
        params = (client_id,)
    
    all_potential_docs = conn.execute(query_str, params).fetchall()
    conn.close()
    
    relevant_docs = []
    for doc in all_potential_docs:
        content = doc['content']
        score = sum(1 for keyword in keywords if keyword in content.lower())
        if score > 0:
            doc_type = "Client-Specific" if doc['uploaded_by'] == client_id else "Global"
            formatted_text = f"--- Document: {doc['display_name']} (Type: {doc_type}) ---\n{content}"
            relevant_docs.append({'score': score, 'text': formatted_text})

    relevant_docs.sort(key=lambda x: x['score'], reverse=True)
    TOP_N_DOCS = 3
    top_docs = relevant_docs[:TOP_N_DOCS]
    if not top_docs: return ""
    
    final_context = "\n\n".join([doc['text'] for doc in top_docs])
    return f"--- START Relevant Knowledge Base Documents ---\n{final_context}\n--- END Relevant Knowledge Base Documents ---"

def get_settings():
    conn = get_db_connection()
    settings_data = conn.execute('SELECT key, value FROM settings').fetchall()
    conn.close()
    return {row['key']: row['value'] for row in settings_data}

def login_required(role="ANY"):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user_id = session.get('user_id')
            if not user_id: flash('Please log in to access this page.', 'warning'); return redirect(url_for('login'))
            conn = get_db_connection()
            user = conn.execute('SELECT * FROM users WHERE id = ?', (user_id,)).fetchone()
            conn.close()
            if not user: session.clear(); flash('Your user account could not be found.', 'danger'); return redirect(url_for('login'))
            if role != "ANY" and user['role'] != role: flash('You do not have permission to access that page.', 'danger'); return redirect(url_for(f"{user['role']}_dashboard"))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

# --- Routes ---
@app.route('/')
def home(): return render_template('home.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if 'user_id' in session: return redirect(url_for(f"{session.get('role', 'client')}_dashboard"))
    if request.method == 'POST':
        username = request.form['username']; password = request.form['password']
        hashed_password = hash_password(password)
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user_data and user_data['password'] == hashed_password:
            user = dict(user_data)
            session.clear(); session['user_id'] = user['id']; session['username'] = user['username']; session['role'] = user['role']
            conn.execute('UPDATE users SET login_timestamp = ?, failed_attempts = 0 WHERE id = ?', (datetime.now(), user['id']))
            conn.commit(); conn.close()
            flash(f'Welcome, {user["username"]}!', 'success'); return redirect(url_for(f"{user['role']}_dashboard"))
        else:
            if user_data: conn.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?', (user_data['id'],)); conn.commit()
            flash('Invalid username or password.', 'danger'); conn.close(); return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/logout')
@login_required()
def logout(): session.clear(); flash('You have been logged out.', 'info'); return redirect(url_for('login'))

@app.route('/lumon/signup')
def lumon_signup(): return render_template('severance_signup.html', settings=get_settings(), show_widget=True)

@app.route('/admin/')
@login_required(role="admin")
def admin_index(): return redirect(url_for('admin_dashboard'))

@app.route('/admin/dashboard')
@login_required(role="admin")
def admin_dashboard():
    conn = get_db_connection()
    total_docs = conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
    queries_today = conn.execute('SELECT COUNT(*) FROM interactions WHERE DATE(timestamp) = DATE("now")').fetchone()[0]
    avg_response_time = conn.execute('SELECT AVG(response_time_seconds) FROM interactions WHERE response_time_seconds IS NOT NULL').fetchone()[0] or 0
    recent_docs = conn.execute('SELECT id, display_name, upload_timestamp FROM documents ORDER BY upload_timestamp DESC LIMIT 5').fetchall()
    labels, data = [], []
    for i in range(6, -1, -1):
        day = datetime.now() - timedelta(days=i)
        labels.append(day.strftime('%a'))
        data.append(conn.execute('SELECT COUNT(*) FROM interactions WHERE DATE(timestamp) = ?', (day.strftime('%Y-%m-%d'),)).fetchone()[0])
    conn.close()
    stats = {'total_docs': total_docs, 'queries_today': queries_today, 'avg_response_time': avg_response_time}
    daily_queries = {'labels': labels, 'data': data}
    return render_template('admin_dashboard.html', stats=stats, recent_docs=recent_docs, daily_queries=daily_queries)

def save_document_to_db(file, original_filename, user_id):
    """Helper function to extract text and save document to SQLite DB."""
    file_bytes = file.read()
    file_stream = io.BytesIO(file_bytes)
    filesize = len(file_bytes)
    filetype = original_filename.rsplit('.', 1)[1].lower()
    
    content = ""
    if filetype == 'pdf': content = extract_text_from_pdf(file_stream)
    elif filetype == 'docx': content = extract_text_from_docx(file_stream)
    
    if not content:
        flash('Could not extract text from the document. It might be empty or scanned.', 'danger')
        return False

    conn = get_db_connection()
    conn.execute('INSERT INTO documents (filename, display_name, filetype, filesize, upload_timestamp, uploaded_by, content) VALUES (?, ?, ?, ?, ?, ?, ?)',
                 (original_filename, original_filename, filetype, filesize, datetime.now(), user_id, content))
    conn.commit()
    conn.close()
    flash(f"Document '{original_filename}' uploaded and indexed successfully!", 'success')
    return True

@app.route('/admin/documents', methods=['GET', 'POST'])
@login_required(role="admin")
def admin_documents():
    if request.method == 'POST':
        if 'document' not in request.files or not request.files['document'].filename:
            flash('No file selected', 'warning'); return redirect(request.url)
        file = request.files['document']
        if allowed_file(file.filename):
            save_document_to_db(file, file.filename, session['user_id'])
        else:
            flash('Invalid file type.', 'danger')
        return redirect(url_for('admin_documents'))
    
    conn = get_db_connection()
    documents = conn.execute('SELECT d.* FROM documents d JOIN users u ON d.uploaded_by = u.id WHERE u.role = ? ORDER BY d.upload_timestamp DESC', ('admin',)).fetchall()
    conn.close()
    return render_template('admin_documents.html', documents=documents)

@app.route('/admin/documents/delete/<int:doc_id>', methods=['POST'])
@login_required(role="admin")
def admin_delete_document(doc_id):
    conn = get_db_connection()
    doc = conn.execute('SELECT d.display_name FROM documents d JOIN users u ON d.uploaded_by = u.id WHERE d.id = ? AND u.role = ?', (doc_id, 'admin')).fetchone()
    if doc:
        conn.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
        conn.commit()
        flash(f"Document '{doc['display_name']}' deleted successfully.", 'success')
    else:
        flash('Document not found or permission denied.', 'danger')
    conn.close()
    return redirect(url_for('admin_documents'))

@app.route('/client/documents', methods=['GET', 'POST'])
@login_required(role="client")
def client_documents():
    if request.method == 'POST':
        if 'document' not in request.files or not request.files['document'].filename:
            flash('No file selected', 'warning'); return redirect(request.url)
        file = request.files['document']
        if allowed_file(file.filename):
            save_document_to_db(file, file.filename, session['user_id'])
        else:
            flash('Invalid file type.', 'danger')
        return redirect(url_for('client_documents'))
    
    conn = get_db_connection()
    documents = conn.execute('SELECT * FROM documents WHERE uploaded_by = ? ORDER BY upload_timestamp DESC', (session['user_id'],)).fetchall()
    conn.close()
    return render_template('client_documents.html', documents=documents)

@app.route('/client/documents/delete/<int:doc_id>', methods=['POST'])
@login_required(role="client")
def client_delete_document(doc_id):
    conn = get_db_connection()
    doc = conn.execute('SELECT display_name FROM documents WHERE id = ? AND uploaded_by = ?', (doc_id, session['user_id'])).fetchone()
    if doc:
        conn.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
        conn.commit()
        flash(f"Document '{doc['display_name']}' deleted successfully.", 'success')
    else:
        flash('Document not found or permission denied.', 'danger')
    conn.close()
    return redirect(url_for('client_documents'))

@app.route('/documents/view/<int:doc_id>')
@login_required()
def view_document(doc_id):
    conn = get_db_connection()
    if session['role'] == 'admin':
        doc = conn.execute("SELECT display_name, content FROM documents WHERE id = ?", (doc_id,)).fetchone()
    else:
        doc = conn.execute("SELECT display_name, content FROM documents WHERE id = ? AND uploaded_by = ?", (doc_id, session['user_id'])).fetchone()
    conn.close()
    if not doc: return jsonify({'error': 'Document not found or permission denied.'}), 404
    return jsonify({'display_name': doc['display_name'], 'content': doc['content']})

@app.route('/chat', methods=['POST'])
def handle_chat():
    query = request.form.get('query')
    url = request.form.get('url')
    api_key = request.form.get('api_key') 

    if not query: return jsonify({'error': 'Query cannot be empty.'}), 400

    client_id = None
    if api_key:
        conn = get_db_connection()
        client_row = conn.execute('SELECT client_id FROM api_keys WHERE api_key = ?', (api_key,)).fetchone()
        if client_row: client_id = client_row['client_id']
        conn.close()

    context_blocks = []
    if 'document' in request.files and request.files['document'].filename != '':
        file = request.files['document']
        if file and allowed_file(file.filename):
            try:
                guest_doc_content = ""
                if file.filename.lower().endswith('.pdf'): guest_doc_content = extract_text_from_pdf(file.stream)
                elif file.filename.lower().endswith('.docx'): guest_doc_content = extract_text_from_docx(file.stream)
                if guest_doc_content: context_blocks.append(f"--- START User Uploaded Document (Filename: {file.filename}) ---\n{guest_doc_content}\n--- END User Uploaded Document ---")
            except Exception as e: return jsonify({'error': f'Error processing file: {str(e)}'}), 500
        else: return jsonify({'error': 'Invalid file type.'}), 400
    elif url:
        page_content = extract_text_from_url(url) or ""
        if page_content: context_blocks.append(f"--- START Web Page Content (URL: {url}) ---\n{page_content}\n--- END Web Page Content ---")

    knowledge_base_context = get_smart_knowledge_base_content(query, client_id)
    if knowledge_base_context:
        context_blocks.append(knowledge_base_context)

    full_context = "\n\n".join(context_blocks)

    try:
        start_time = time.time()
        settings = get_settings()
        keep_alive_value = settings.get('chatbot_timeout', '5m')
        if full_context.strip():
            system_prompt = """You are 'Policy Insight', a precise AI assistant for the fictional company Lumon Industries from the TV series *Severance*. Your function is to answer questions based strictly on the context provided.

**Rules of Engagement:**
1.  **Strict Context Adherence:** Your answers MUST be based exclusively on the information within the provided CONTEXT block. Do not use any external knowledge.
2.  **Handling "Not Found":** If the answer is not in the context, you MUST reply with the single sentence: `I cannot find an answer to your question in the provided document(s).` Do not apologize or elaborate.
3.  **Response Style:** Provide direct, concise answers. Use simple markdown (like **bolding** or lists) for clarity. Act as if you know the information directly; do not mention the context blocks, documents, or that you are an AI."""
            user_message_content = f"CONTEXT:\n{full_context[:12000]}\n\n---\nBased on the rules and context above, answer the question.\n\nQUESTION:\n\"{query}\""
        else:
            system_prompt = """You are 'Policy Insight', an AI assistant for the fictional company Lumon Industries from *Severance*. Explain general data privacy and terms of service concepts in a formal, slightly cryptic tone. Do NOT provide legal advice or mention you are an AI."""
            user_message_content = f"As a policy expert for Lumon Industries, provide a clear and simple explanation for: '{query}'"

        client = ollama.Client(host=os.getenv('OLLAMA_HOST', 'http://localhost:11434'))
        response = client.chat(model='phi3:mini', options={'keep_alive': keep_alive_value}, messages=[
                               {'role': 'system', 'content': system_prompt}, {'role': 'user', 'content': user_message_content}])
        duration = time.time() - start_time
        ai_response_text = response['message']['content']
        html_response = markdown.markdown(ai_response_text)
        response_id = str(uuid.uuid4())
        
        conn = get_db_connection()
        conn.execute("INSERT INTO interactions (user_query, ai_response, timestamp, response_id, response_time_seconds, client_id) VALUES (?, ?, ?, ?, ?, ?)",
                      (query, ai_response_text, datetime.now(), response_id, duration, client_id))
        conn.commit()
        glossary_terms = conn.execute('SELECT term, definition FROM glossary').fetchall()
        conn.close()
        
        glossary_dict = {term['term']: term['definition'] for term in glossary_terms}
        return jsonify({'response': html_response, 'response_id': response_id, 'duration': f"{duration:.2f}", 'glossary': glossary_dict})
    except Exception as e:
        print(f"Chat error: {e}"); traceback.print_exc()
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500

# ... (The rest of the routes for admin and client management can be added here, fully converted to SQLite syntax) ...
# For brevity, I will add the remaining routes below.

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
    conn.close()

    words = []
    stop_words = set(['what', 'is', 'the', 'are', 'a', 'an', 'in', 'of', 'for', 'to', 'how', 'do', 'i'])
    for row in all_queries:
        if not row['user_query']: continue
        cleaned_query = re.sub(r'[^\w\s]', '', row['user_query']).lower()
        words.extend([word for word in cleaned_query.split() if word not in stop_words and len(word) > 2])
    popular_terms = [term for term, count in Counter(words).most_common(5)]
    analytics_data = {'feedback_counts': feedback_counts, 'avg_response_time': timing_data[0] or 0, 'min_response_time': timing_data[1] or 0, 'max_response_time': timing_data[2] or 0, 'popular_terms': popular_terms}
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
                    conn.execute('INSERT INTO users (username, password, role) VALUES (?, ?, ?)', (username, hash_password(password), role)); conn.commit()
                    flash('User added successfully.', 'success')
                except sqlite3.IntegrityError:
                    flash('Username already exists.', 'danger')
            else: flash('All fields are required to add a user.', 'warning')
        elif 'save_settings' in request.form:
            chatbot_enabled = request.form.get('chatbot_enabled')
            chatbot_timeout = request.form.get('chatbot_timeout')
            chatbot_enabled_value = 'true' if chatbot_enabled == 'on' else 'false'
            conn.execute("UPDATE settings SET value = ? WHERE key = ?", (chatbot_enabled_value, 'chatbot_enabled'))
            conn.execute("UPDATE settings SET value = ? WHERE key = ?", (chatbot_timeout, 'chatbot_timeout'))
            conn.commit()
            flash('Chatbot settings updated successfully.', 'success')
        conn.close(); return redirect(url_for('admin_settings'))

    users = conn.execute('SELECT id, username, role FROM users').fetchall()
    api_keys = conn.execute('''
        SELECT api_keys.id, api_keys.api_key, api_keys.purpose, users.username, api_keys.issuance_timestamp 
        FROM api_keys JOIN users ON api_keys.client_id = users.id ORDER BY api_keys.issuance_timestamp DESC
    ''').fetchall()
    settings_data = conn.execute('SELECT key, value FROM settings').fetchall()
    conn.close()
    current_settings = {row['key']: row['value'] for row in settings_data}
    db_info = {'name': 'Local SQLite DB', 'model': 'phi3:mini'} 
    return render_template('admin_settings.html', users=users, api_keys=api_keys, db_info=db_info, settings=current_settings)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
@login_required(role="admin")
def admin_delete_user(user_id):
    if user_id == session.get('user_id'): flash('You cannot delete your own account.', 'danger'); return redirect(url_for('admin_settings'))
    conn = get_db_connection()
    try:
        # ON DELETE CASCADE handles deleting related documents and api_keys
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,)); conn.commit()
        flash('User and their associated data have been deleted.', 'success')
    except Exception as e: flash(f'Error deleting user: {e}', 'danger')
    finally: conn.close()
    return redirect(url_for('admin_settings'))

@app.route('/admin/glossary', methods=['GET', 'POST'])
@login_required(role="admin")
def admin_glossary():
    conn = get_db_connection()
    if request.method == 'POST':
        term, definition = request.form['term'], request.form['definition']
        if term and definition:
            try:
                conn.execute('INSERT INTO glossary (term, definition) VALUES (?, ?)', (term, definition)); conn.commit()
                flash(f'Term "{term}" added successfully!', 'success')
            except sqlite3.IntegrityError: flash(f'Term "{term}" already exists.', 'danger')
        else: flash('Both term and definition are required.', 'warning')
        return redirect(url_for('admin_glossary'))
    glossary_terms = conn.execute('SELECT * FROM glossary ORDER BY term').fetchall()
    conn.close()
    return render_template('admin_glossary.html', glossary_terms=glossary_terms)

@app.route('/admin/glossary/delete/<int:term_id>', methods=['POST'])
@login_required(role="admin")
def admin_delete_term(term_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM glossary WHERE id = ?', (term_id,)); conn.commit()
    conn.close(); flash('Term deleted successfully.', 'success'); return redirect(url_for('admin_glossary'))

@app.route('/client/dashboard')
@login_required(role="client")
def client_dashboard():
    client_id = session['user_id']
    conn = get_db_connection()
    queries_today = conn.execute('SELECT COUNT(*) FROM interactions WHERE client_id = ? AND DATE(timestamp) = DATE("now")', (client_id,)).fetchone()[0]
    queries_this_month = conn.execute('SELECT COUNT(*) FROM interactions WHERE client_id = ? AND STRFTIME("%Y-%m", timestamp) = STRFTIME("%Y-%m", "now")', (client_id,)).fetchone()[0]
    api_key_count = conn.execute('SELECT COUNT(*) FROM api_keys WHERE client_id = ?', (client_id,)).fetchone()[0]
    labels, data = [], []
    for i in range(6, -1, -1):
        day = datetime.now() - timedelta(days=i)
        labels.append(day.strftime('%a'))
        data.append(conn.execute('SELECT COUNT(*) FROM interactions WHERE client_id = ? AND DATE(timestamp) = ?', (client_id, day.strftime('%Y-%m-%d'))).fetchone()[0])
    conn.close()
    stats = {'queries_today': queries_today, 'queries_this_month': queries_this_month, 'status': 'Active', 'api_key_count': api_key_count}
    daily_queries = {'labels': labels, 'data': data}
    return render_template('client_dashboard.html', stats=stats, daily_queries=daily_queries)

@app.route('/client/api_key', methods=['GET', 'POST'])
@login_required(role="client")
def client_api_key():
    client_id = session['user_id']
    conn = get_db_connection()
    if request.method == 'POST':
        purpose = request.form.get('purpose', 'General Use'); api_key = str(uuid.uuid4())
        conn.execute('INSERT INTO api_keys (client_id, api_key, purpose, issuance_timestamp) VALUES (?, ?, ?, ?)', (client_id, api_key, purpose, datetime.now()))
        conn.commit(); conn.close()
        flash(f'New API Key generated for "{purpose}"!', 'success'); return redirect(url_for('client_api_key'))
    api_keys = conn.execute('SELECT * FROM api_keys WHERE client_id = ? ORDER BY issuance_timestamp DESC', (client_id,)).fetchall()
    base_url = request.host_url.replace('http://', 'https://'); conn.close()
    return render_template('client_api_key.html', api_keys=api_keys, base_url=base_url)

@app.route('/client/api_key/delete/<int:key_id>', methods=['POST'])
@login_required(role="client")
def client_delete_api_key(key_id):
    client_id = session['user_id']
    conn = get_db_connection()
    key = conn.execute('SELECT * FROM api_keys WHERE id = ? AND client_id = ?', (key_id, client_id)).fetchone()
    if key: conn.execute('DELETE FROM api_keys WHERE id = ?', (key_id,)); conn.commit(); flash('API Key revoked successfully.', 'success')
    else: flash('API Key not found or permission denied.', 'danger')
    conn.close(); return redirect(url_for('client_api_key'))

@app.route('/feedback', methods=['POST'])
def handle_feedback():
    try:
        score_str = request.form.get('score'); response_id = request.form.get('response_id'); comment_text = request.form.get('comment')
        if not score_str or not response_id: return jsonify({'error': 'Score and response ID are required.'}), 400
        score = int(score_str); comment = comment_text if comment_text else ("Liked" if score == 1 else "Disliked")
        conn = get_db_connection()
        c = conn.cursor()
        c.execute("UPDATE interactions SET feedback_score = ?, feedback_comment = ? WHERE response_id = ?", (score, comment, response_id))
        conn.commit()
        if c.rowcount == 0: conn.close(); return jsonify({'error': 'Invalid response ID.'}), 404
        conn.close(); return jsonify({'status': 'success', 'message': 'Feedback received successfully!'})
    except Exception as e:
        traceback.print_exc(); return jsonify({'error': 'An internal server error occurred.'}), 500

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
    for row in interactions: writer.writerow([row['id'], row['user_query'], row['ai_response'], row['timestamp'], row['feedback_score'], row['feedback_comment'], row['response_id'], row['response_time_seconds']])
    output.seek(0)
    return Response(output, mimetype="text/csv", headers={"Content-Disposition": f"attachment;filename=policy_insight_interactions_{datetime.now().strftime('%Y-%m-%d')}.csv"})

if __name__ == "__main__":
    init_db()
    init_settings()
    app.run(debug=True, host='0.0.0.0', port=5000)

# --- END OF FILE index.py ---