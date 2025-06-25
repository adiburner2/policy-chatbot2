# --- START OF FILE index.py ---

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
import os
from datetime import datetime, timedelta
import uuid
import traceback
import markdown
import time
from collections import Counter
import re
import io
import csv
from flask import Response 

# Document/Web Parsing Libraries
import ollama
import pdfplumber
from bs4 import BeautifulSoup
import requests
import docx

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-very-secret-key-that-is-long')
DATABASE = 'policy_chatbot.db'
UPLOAD_FOLDER = 'uploads'
os.makedirs(UPLOAD_FOLDER, exist_ok=True)
ALLOWED_EXTENSIONS = {'pdf', 'docx'}
app.config['UPLOAD_FOLDER'] = UPLOAD_FOLDER

# --- Database Initialization and Settings Management ---
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        # Create tables (no changes here)
        c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, login_timestamp DATETIME, failed_attempts INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS documents (
                        id INTEGER PRIMARY KEY, 
                        filename TEXT NOT NULL, 
                        display_name TEXT NOT NULL,
                        filetype TEXT NOT NULL, 
                        filesize INTEGER NOT NULL, 
                        upload_timestamp DATETIME, 
                        uploaded_by INTEGER, 
                        FOREIGN KEY(uploaded_by) REFERENCES users(id)
                    )''')
        c.execute('''CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY, client_id INTEGER, api_key TEXT NOT NULL, purpose TEXT, issuance_timestamp DATETIME, FOREIGN KEY(client_id) REFERENCES users(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS interactions (id INTEGER PRIMARY KEY, user_query TEXT, ai_response TEXT, timestamp DATETIME, feedback_score INTEGER, feedback_comment TEXT, response_id TEXT, response_time_seconds REAL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS glossary (id INTEGER PRIMARY KEY AUTOINCREMENT, term TEXT UNIQUE NOT NULL, definition TEXT NOT NULL)''')
        c.execute('''CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL)''')
        
        # Populate initial users if table is empty
        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()[0] == 0:
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', hash_password('admin123'), 'admin'))
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('client', hash_password('client123'), 'client'))

        # --- NEW: Create a permanent, known API key for the 'client' user (ID 2) ---
        c.execute(
            "INSERT OR IGNORE INTO api_keys (id, client_id, api_key, purpose, issuance_timestamp) VALUES (?, ?, ?, ?, ?)",
            (1, 2, '11111111-1111-1111-1111-111111111111', 'Default Key for Policy Page Demo', datetime.now().isoformat())
        )
        # --- END NEW ---

        if c.execute("SELECT COUNT(*) FROM glossary").fetchone()[0] == 0:
            sample_terms = [
                ('GDPR', 'The General Data Protection Regulation is a regulation in EU law on data protection and privacy.'),
                ('Cookies', 'Small files stored on a user\'s computer by their web browser at the request of a website.'),
                ('Personal Data', 'Any information that relates to an identified or identifiable individual.'),
                ('Third-party', 'An entity other than the user or the service provider, who may receive user data.')
            ]
            c.executemany("INSERT INTO glossary (term, definition) VALUES (?, ?)", sample_terms)
        
        conn.commit()

def init_settings():
    """Initializes the settings table with default values if they don't exist."""
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
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

def extract_text_from_pdf(file_path_or_stream):
    text = ""
    with pdfplumber.open(file_path_or_stream) as pdf:
        for page in pdf.pages:
            text += page.extract_text() or ""
    return text

def extract_text_from_docx(file_path_or_stream):
    doc = docx.Document(file_path_or_stream)
    return "\n".join([para.text for para in doc.paragraphs])

def extract_text_from_url(url):
    try:
        headers = {'User-Agent': 'Mozilla/5.0'}
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')
        main_content = soup.find('main') or soup.find('article') or soup.find(id='content') or soup.find(id='policy-content')
        target_soup = main_content if main_content else soup.body
        if not target_soup: return None
        for element in target_soup(['script', 'style', 'nav', 'header', 'footer']): element.extract()
        return " ".join(text for text in target_soup.stripped_strings if text)
    except requests.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return None

def get_knowledge_base_content(client_id=None):
    """
    Reads all admin-uploaded (global) documents and, if a client_id is provided,
    also reads that client's specific documents.
    """
    conn = get_db_connection()
    
    # Start with a base query for the admin documents (user_id = 1)
    query = 'SELECT filename, display_name, filetype FROM documents WHERE uploaded_by = ?'
    # Start with the parameter for the admin user
    params = [1] 
    
    # If a client_id is provided, add their documents to the query
    if client_id:
        query += ' OR uploaded_by = ?'
        params.append(client_id)
        
    documents = conn.execute(query, tuple(params)).fetchall()
    conn.close()
    
    knowledge_base = ""
    for doc in documents:
        # Use display_name for a more readable context marker for the AI
        file_label = doc['display_name'] 
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc['filename'])
        
        if os.path.exists(file_path):
            try:
                content = ""
                if doc['filetype'] == 'pdf':
                    content = extract_text_from_pdf(file_path)
                elif doc['filetype'] == 'docx':
                    content = extract_text_from_docx(file_path)
                
                if content:
                    knowledge_base += f"\n\n--- Start of Knowledge Base Document: {file_label} ---\n"
                    knowledge_base += content
                    knowledge_base += f"\n--- End of Knowledge Base Document: {file_label} ---\n"
            except Exception as e:
                print(f"Error reading document {doc['filename']}: {e}")
    return knowledge_base.strip()

def get_settings():
    """Fetches all settings from the DB and returns them as a dictionary."""
    conn = get_db_connection()
    settings_data = conn.execute('SELECT key, value FROM settings').fetchall()
    conn.close()
    return {row['key']: row['value'] for row in settings_data}

# --- Core Routes ---
@app.route('/logout')
def logout():
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/policy-page')
def policy_example():
    settings = get_settings() # Get settings to control widget visibility
    try:
        with open('Example-Doc.txt', 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        content = "The example document could not be found."
    return render_template('policy_page.html', content=content, settings=settings)

# --- Login Route ---
@app.route('/', methods=['GET', 'POST'])
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        conn = get_db_connection()
        user_data = conn.execute('SELECT * FROM users WHERE username = ?', (username,)).fetchone()
        if user_data and user_data['password'] == hashed_password:
            user = dict(user_data)
            conn.execute('UPDATE users SET login_timestamp = ?, failed_attempts = 0 WHERE id = ?', (datetime.now(), user['id']))
            conn.commit()
            conn.close()
            flash(f'Welcome, {user["username"]}!', 'success')
            if user['role'] == 'admin':
                return redirect(url_for('admin_dashboard'))
            elif user['role'] == 'client':
                return redirect(url_for('client_dashboard'))
        else:
            if user_data:
                conn.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?', (user_data['id'],))
                conn.commit()
            conn.close()
            flash('Invalid credentials', 'danger')
            return redirect(url_for('login'))
    return render_template('login.html')
    
# --- Admin Routes ---
@app.route('/admin/')
def admin_index():
    return redirect(url_for('admin_dashboard'))

@app.route('/admin/dashboard')
def admin_dashboard():
    conn = get_db_connection()
    total_docs = conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    queries_today = conn.execute('SELECT COUNT(*) FROM interactions WHERE DATE(timestamp) = DATE(?)', (today_start.isoformat(),)).fetchone()[0]
    avg_response_time = conn.execute('SELECT AVG(response_time_seconds) FROM interactions WHERE response_time_seconds IS NOT NULL').fetchone()[0] or 0
    recent_docs = conn.execute('SELECT filename, upload_timestamp FROM documents ORDER BY upload_timestamp DESC LIMIT 5').fetchall()
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
def admin_documents():
    conn = get_db_connection()
    if request.method == 'POST':
        if 'document' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['document']
        if file.filename == '' or not allowed_file(file.filename):
            flash('Invalid file or file type. Only PDF and DOCX are allowed.', 'danger')
            return redirect(request.url)

        filename = file.filename
        file_bytes = file.read()
        filesize = len(file_bytes)
        filetype = filename.rsplit('.', 1)[1].lower()
        upload_time = datetime.now()
        
        # Admin uploads have the same filename and display_name
        safe_filename = filename 
        display_name = filename
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
        
        # Prevent overwriting existing files
        if os.path.exists(file_path):
            flash(f"A file named '{filename}' already exists. Please rename and upload again.", 'warning')
            return redirect(url_for('admin_documents'))

        with open(file_path, 'wb') as f:
            f.write(file_bytes)
        
        # UPDATED: Add display_name to insert
        conn.execute('INSERT INTO documents (filename, display_name, filetype, filesize, upload_timestamp, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)',
                     (safe_filename, display_name, filetype, filesize, upload_time.isoformat(), 1)) # Admin user ID is 1
        conn.commit()
        flash('Document uploaded successfully!', 'success')
        return redirect(url_for('admin_documents'))
    
    documents = conn.execute('SELECT * FROM documents ORDER BY upload_timestamp DESC').fetchall()
    conn.close()
    return render_template('admin_documents.html', documents=documents)

@app.route('/admin/documents/delete/<int:doc_id>', methods=['POST'])
def admin_delete_document(doc_id):
    conn = get_db_connection()
    doc = conn.execute('SELECT filename FROM documents WHERE id = ?', (doc_id,)).fetchone()
    if doc:
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc['filename'])
            if os.path.exists(file_path): os.remove(file_path)
            conn.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
            conn.commit()
            flash(f"Document '{doc['filename']}' deleted successfully.", 'success')
        except Exception as e:
            flash(f"Error deleting document: {e}", 'danger')
    else:
        flash('Document not found.', 'danger')
    conn.close()
    return redirect(url_for('admin_documents'))

@app.route('/admin/analytics')
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
    
    analytics_data = {
        'feedback_counts': feedback_counts,
        'avg_response_time': timing_data[0] or 0,
        'min_response_time': timing_data[1] or 0,
        'max_response_time': timing_data[2] or 0,
        'popular_terms': popular_terms
    }
    conn.close()
    return render_template('admin_analytics.html', interactions=interactions, analytics=analytics_data)

@app.route('/admin/settings', methods=['GET', 'POST'])
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
    db_info = {'name': DATABASE, 'model': 'phi3:mini'} 
    return render_template('admin_settings.html', users=users, api_keys=api_keys, db_info=db_info, settings=current_settings)

@app.route('/admin/users/delete/<int:user_id>', methods=['POST'])
def admin_delete_user(user_id):
    if user_id == 1:
        flash('Cannot delete the primary admin account.', 'danger')
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
def admin_delete_term(term_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM glossary WHERE id = ?', (term_id,))
    conn.commit()
    conn.close()
    flash('Term deleted successfully.', 'success')
    return redirect(url_for('admin_glossary'))

# --- Client Routes ---
@app.route('/client/dashboard')
def client_dashboard():
    conn = get_db_connection()
    # This is a placeholder for a real client session. We'll use ID 2.
    client_id_to_use = 2 

    # Simplified analytics: counts all interactions. In a real app, you would
    # link interactions to clients via their API key.
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    queries_today = conn.execute('SELECT COUNT(*) FROM interactions WHERE DATE(timestamp) = DATE(?)', (today_start.isoformat(),)).fetchone()[0]
    
    start_of_month = datetime.now().replace(day=1, hour=0, minute=0, second=0, microsecond=0)
    queries_this_month = conn.execute('SELECT COUNT(*) FROM interactions WHERE timestamp >= ?', (start_of_month.isoformat(),)).fetchone()[0]

    stats = {
        'queries_today': queries_today,
        'queries_this_month': queries_this_month,
        'status': 'Active' 
    }
    conn.close()
    return render_template('client_dashboard.html', stats=stats)


@app.route('/client/api_key', methods=['GET', 'POST'])
def client_api_key():
    conn = get_db_connection()
    client_id_to_use = 2 # Placeholder for a real client session

    if request.method == 'POST':
        purpose = request.form.get('purpose', 'General Use')
        api_key = str(uuid.uuid4())
        conn.execute('INSERT INTO api_keys (client_id, api_key, purpose, issuance_timestamp) VALUES (?, ?, ?, ?)',
                     (client_id_to_use, api_key, purpose, datetime.now().isoformat()))
        conn.commit()
        flash(f'New API Key generated for "{purpose}"!', 'success')
        return redirect(url_for('client_api_key'))
    
    api_keys = conn.execute('SELECT * FROM api_keys WHERE client_id = ? ORDER BY issuance_timestamp DESC', (client_id_to_use,)).fetchall()
    
    # --- NEW: Get the base URL to pass to the template ---
    # This will be 'http://127.0.0.1:5000/' locally and 'https://your-app.onrender.com/' when deployed.
    base_url = request.host_url
    
    conn.close()
    return render_template('client_api_key.html', api_keys=api_keys, base_url=base_url)

@app.route('/client/api_key/delete/<int:key_id>', methods=['POST'])
def client_delete_api_key(key_id):
    client_id_to_use = 2 # Placeholder for a real client session
    conn = get_db_connection()
    key = conn.execute('SELECT * FROM api_keys WHERE id = ? AND client_id = ?', (key_id, client_id_to_use)).fetchone()
    if key:
        conn.execute('DELETE FROM api_keys WHERE id = ?', (key_id,))
        conn.commit()
        flash('API Key revoked successfully.', 'success')
    else:
        flash('API Key not found or you do not have permission to revoke it.', 'danger')
    conn.close()
    return redirect(url_for('client_api_key'))

@app.route('/client/documents', methods=['GET', 'POST'])
def client_documents():
    conn = get_db_connection()
    client_id_to_use = 2 # Placeholder for a real client session

    if request.method == 'POST':
        if 'document' not in request.files:
            flash('No file part', 'danger')
            return redirect(request.url)
        file = request.files['document']
        if file.filename == '' or not allowed_file(file.filename):
            flash('Invalid file or file type. Only PDF and DOCX are allowed.', 'danger')
            return redirect(request.url)

        original_filename = file.filename
        # Create a unique filename for storage to prevent clashes
        safe_filename = f"client_{client_id_to_use}_{uuid.uuid4().hex[:8]}_{original_filename}"
        
        file_bytes = file.read()
        filesize = len(file_bytes)
        filetype = original_filename.rsplit('.', 1)[1].lower()
        upload_time = datetime.now()
        
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], safe_filename)
        with open(file_path, 'wb') as f:
            f.write(file_bytes)
        
        # UPDATED: Store both safe_filename and original_filename (as display_name)
        conn.execute('INSERT INTO documents (filename, display_name, filetype, filesize, upload_timestamp, uploaded_by) VALUES (?, ?, ?, ?, ?, ?)',
                     (safe_filename, original_filename, filetype, filesize, upload_time.isoformat(), client_id_to_use))
        conn.commit()
        flash(f"Document '{original_filename}' uploaded successfully!", 'success')
        return redirect(url_for('client_documents'))
    
    # Fetch only documents uploaded by this specific client
    documents = conn.execute('SELECT * FROM documents WHERE uploaded_by = ? ORDER BY upload_timestamp DESC', (client_id_to_use,)).fetchall()
    conn.close()
    return render_template('client_documents.html', documents=documents)

@app.route('/client/documents/delete/<int:doc_id>', methods=['POST'])
def client_delete_document(doc_id):
    client_id_to_use = 2 # Placeholder for a real client session
    conn = get_db_connection()
    doc = conn.execute('SELECT filename FROM documents WHERE id = ? AND uploaded_by = ?', (doc_id, client_id_to_use)).fetchone()
    if doc:
        try:
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], doc['filename'])
            if os.path.exists(file_path): os.remove(file_path)
            conn.execute('DELETE FROM documents WHERE id = ?', (doc_id,))
            conn.commit()
            flash('Document deleted successfully.', 'success')
        except Exception as e:
            flash(f"Error deleting document: {e}", 'danger')
    else:
        flash('Document not found or you do not have permission to delete it.', 'danger')
    conn.close()
    return redirect(url_for('client_documents'))

# --- Chat and Feedback Routes ---
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

    # --- Context Gathering Logic (No changes here, it is correct) ---
    full_context = ""
    
    # 1. Prioritize guest-uploaded document
    if 'document' in request.files and request.files['document'].filename != '':
        file = request.files['document']
        if file and allowed_file(file.filename):
            try:
                guest_doc_content = ""
                if file.filename.lower().endswith('.pdf'):
                    guest_doc_content = extract_text_from_pdf(file.stream)
                elif file.filename.lower().endswith('.docx'):
                    guest_doc_content = extract_text_from_docx(file.stream)
                
                full_context += f"--- START User Uploaded Document: {file.filename} ---\n{guest_doc_content}\n--- END User Uploaded Document ---\n\n"
            except Exception as e:
                traceback.print_exc()
                return jsonify({'error': f'Error processing file: {str(e)}'}), 500
        else:
            return jsonify({'error': 'Invalid file type.'}), 400
            
    # 2. Or, use the page URL content as the primary context.
    elif url:
        page_content = extract_text_from_url(url) or ""
        if page_content:
            full_context += f"--- START Current Web Page Content ---\n{page_content}\n--- END Current Web Page Content ---\n\n"

    # 3. Always add the global and client-specific knowledge base
    knowledge_base_content = get_knowledge_base_content(client_id)
    if knowledge_base_content:
        full_context += f"--- START Knowledge Base Documents ---\n{knowledge_base_content}\n--- END Knowledge Base Documents ---"

    # --- NEW, MORE ASSERTIVE PROMPT ---
    try:
        start_time = time.time()
        settings = get_settings()
        keep_alive_value = settings.get('chatbot_timeout', '5m')

        if full_context.strip():
            # This is the RAG prompt that guides the AI on how to use the structured context
            system_prompt = """You are a helpful AI assistant named Policy Insight. Your only function is to answer questions based on the context provided below.

**Rules:**
1.  **Source Priority:** You MUST prioritize information in this exact order:
    1.  `User Uploaded Document` (if present)
    2.  `Current Web Page Content` (if present)
    3.  `Knowledge Base Documents`
2.  **Conflict Resolution:** If a newer or more specific document (like a user upload or the current page) contradicts an older one in the knowledge base, the newer one is ALWAYS correct.
3.  **Strictly Contextual:** Your answer MUST be derived *only* from the text in the provided context. Do not use any external knowledge.
4.  **Handle Missing Information:** If the answer cannot be found in the provided context, you MUST reply with the single sentence: "I cannot find an answer to your question in the provided document(s)." Do not add apologies or other text.
5.  **Clean and Natural Responses:**
    - Do NOT mention the names of the source blocks (e.g., do not say "According to the Knowledge Base...").
    - Do NOT mention that you are an AI or refer to your knowledge cutoff date.
    - Provide concise, direct answers using simple markdown for formatting.
    - Do NOT give legal advice.
"""
            user_message_content = f"""CONTEXT:
{full_context[:8000]} 

---
Based on the rules and context above, answer the following question.

QUESTION:
"{query}"
"""
        else:
            # This is the general knowledge prompt for when no context is available
            system_prompt = "You are 'Policy Insight', an AI assistant that explains general data privacy and terms of service concepts in simple terms.\n- Do NOT give legal advice.\n- Keep answers concise and clear.\n- Use markdown for formatting."
            user_message_content = f"As a policy expert, please provide a clear and simple explanation for: '{query}'"

        client = ollama.Client(host=os.getenv('OLLAMA_HOST', 'http://localhost:11434'))
        response = client.chat(
            model='phi3:mini',
            options={'keep_alive': keep_alive_value},
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_message_content}
            ]
        )
        
        duration = time.time() - start_time
        ai_response_text = response['message']['content']
        html_response = markdown.markdown(ai_response_text)
        response_id = str(uuid.uuid4())

        with sqlite3.connect(DATABASE) as conn:
            conn.execute("INSERT INTO interactions (user_query, ai_response, timestamp, response_id, response_time_seconds) VALUES (?, ?, ?, ?, ?)",
                         (query, ai_response_text, datetime.now().isoformat(), response_id, duration))
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
def admin_analytics_export():
    """
    Generates and returns a CSV file of all chat interactions.
    """
    conn = get_db_connection()
    interactions = conn.execute('SELECT * FROM interactions ORDER BY timestamp DESC').fetchall()
    conn.close()

    # io.StringIO to build the CSV in memory instead of writing to a physical file
    output = io.StringIO()
    writer = csv.writer(output)

    # Write the header row
    header = [
        'ID', 'User Query', 'AI Response', 'Timestamp', 
        'Feedback Score (1=Like, -1=Dislike)', 'Feedback Comment', 
        'Response ID', 'Response Time (s)'
    ]
    writer.writerow(header)

    # Write the data rows
    for row in interactions:
        writer.writerow([
            row['id'],
            row['user_query'],
            row['ai_response'],
            row['timestamp'],
            row['feedback_score'],
            row['feedback_comment'],
            row['response_id'],
            row['response_time_seconds']
        ])

    # Move the "cursor" to the beginning of the memory-based file
    output.seek(0)

    # Create a Flask response object
    return Response(
        output,
        mimetype="text/csv",
        headers={"Content-Disposition": f"attachment;filename=policy_insight_interactions_{datetime.now().strftime('%Y-%m-%d')}.csv"}
    )



if __name__ == "__main__":
    init_db()
    init_settings() # Initialize settings on startup
    app.run(debug=True, port=5000)