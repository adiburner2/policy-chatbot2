# --- START OF FILE index.py ---

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
import os
from datetime import datetime, timedelta  # Add timedelta
import uuid
import traceback
import markdown
import time
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

# --- Database Initialization ---
def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (id INTEGER PRIMARY KEY, username TEXT UNIQUE NOT NULL, password TEXT NOT NULL, role TEXT NOT NULL, login_timestamp DATETIME, failed_attempts INTEGER DEFAULT 0)''')
        c.execute('''CREATE TABLE IF NOT EXISTS documents (id INTEGER PRIMARY KEY, filename TEXT NOT NULL, filetype TEXT NOT NULL, filesize INTEGER NOT NULL, upload_timestamp DATETIME, uploaded_by INTEGER, FOREIGN KEY(uploaded_by) REFERENCES users(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS api_keys (id INTEGER PRIMARY KEY, client_id INTEGER, api_key TEXT NOT NULL, purpose TEXT, issuance_timestamp DATETIME, FOREIGN KEY(client_id) REFERENCES users(id))''')
        c.execute('''CREATE TABLE IF NOT EXISTS interactions (id INTEGER PRIMARY KEY, user_query TEXT, ai_response TEXT, timestamp DATETIME, feedback_score INTEGER, feedback_comment TEXT, response_id TEXT, response_time_seconds REAL)''')
        
        # --- Add glossary table and sample data ---
        c.execute('''CREATE TABLE IF NOT EXISTS glossary (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            term TEXT UNIQUE NOT NULL,
            definition TEXT NOT NULL
        )''')
        # Add some sample terms for testing
        c.execute("SELECT COUNT(*) FROM glossary")
        if c.fetchone()[0] == 0:
            sample_terms = [
                ('GDPR', 'The General Data Protection Regulation is a regulation in EU law on data protection and privacy.'),
                ('Cookies', 'Small files stored on a user\'s computer by their web browser at the request of a website.'),
                ('Personal Data', 'Any information that relates to an identified or identifiable individual.'),
                ('Third-party', 'An entity other than the user or the service provider, who may receive user data.')
            ]
            c.executemany("INSERT INTO glossary (term, definition) VALUES (?, ?)", sample_terms)
            conn.commit()
        # --- End glossary addition ---

        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()[0] == 0:
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('admin', hash_password('admin123'), 'admin'))
            c.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", ('client', hash_password('client123'), 'client'))
            conn.commit()
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
        # For local development, requests to the same app can hang.
        # It's generally fine for production but good to be aware of.
        response = requests.get(url, headers=headers, timeout=15)
        response.raise_for_status()
        soup = BeautifulSoup(response.content, 'html.parser')

        # Prioritize main content areas for cleaner text extraction
        main_content = soup.find('main') or soup.find('article') or soup.find(id='content') or soup.find(id='policy-content')
        target_soup = main_content if main_content else soup.body
        
        if not target_soup:
            return None # Should not happen if page has a body

        for element in target_soup(['script', 'style', 'nav', 'header', 'footer']):
            element.extract()
            
        return " ".join(text for text in target_soup.stripped_strings if text)
    except requests.RequestException as e:
        print(f"Error fetching URL {url}: {e}")
        return None

# --- Core Routes ---
@app.route('/')
def home():
    return render_template('login.html')

@app.route('/logout')
def logout():
    # In a real app, you'd clear session data here.
    # session.clear()
    flash('You have been logged out.', 'info')
    return redirect(url_for('login'))

@app.route('/policy-page')
def policy_example():
    try:
        # This route populates the page with content from a local file for demonstration.
        # The chatbot widget then correctly scrapes this content via its URL.
        with open('Example-Doc.txt', 'r', encoding='utf-8') as f:
            content = f.read()
    except FileNotFoundError:
        content = "The example document could not be found."
    return render_template('policy_page.html', content=content)

# --- Login Route (No changes needed) ---
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            # This logic needs to be fixed to handle the hashed password correctly.
            # For now, we'll keep it simple for demonstration. A proper user session system is needed.
            c.execute('SELECT * FROM users WHERE username = ?', (username,))
            user_data = c.fetchone()

            if user_data and user_data[2] == hashed_password:
                user = {'id': user_data[0], 'username': user_data[1], 'role': user_data[3]}
                c.execute('UPDATE users SET login_timestamp = ?, failed_attempts = 0 WHERE id = ?', (datetime.now(), user['id']))
                conn.commit()
                flash(f'Welcome, {user["username"]}!', 'success')
                if user['role'] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user['role'] == 'client':
                    return redirect(url_for('client_dashboard'))
            else:
                if user_data:
                    c.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE id = ?', (user_data[0],))
                    conn.commit()
                flash('Invalid credentials', 'danger')
                return redirect(url_for('login'))

    return render_template('login.html')
    
# --- Admin Routes ---
@app.route('/admin/dashboard')
def admin_dashboard():
    conn = get_db_connection()
    
    # Quick Stats
    total_docs = conn.execute('SELECT COUNT(*) FROM documents').fetchone()[0]
    today_start = datetime.now().replace(hour=0, minute=0, second=0, microsecond=0)
    queries_today = conn.execute('SELECT COUNT(*) FROM interactions WHERE timestamp >= ?', (today_start.isoformat(),)).fetchone()[0]
    avg_response_time = conn.execute('SELECT AVG(response_time_seconds) FROM interactions WHERE response_time_seconds IS NOT NULL').fetchone()[0] or 0
    
    # Recent Docs
    recent_docs = conn.execute('SELECT filename, upload_timestamp FROM documents ORDER BY upload_timestamp DESC LIMIT 5').fetchall()
    
    # Queries per day
    labels = []
    data = []
    for i in range(6, -1, -1):
        day = datetime.now() - timedelta(days=i)
        day_start = day.strftime('%Y-%m-%d 00:00:00')
        day_end = day.strftime('%Y-%m-%d 23:59:59')
        labels.append(day.strftime('%a'))
        count = conn.execute('SELECT COUNT(*) FROM interactions WHERE timestamp BETWEEN ? AND ?', (day_start, day_end)).fetchone()[0]
        data.append(count)
        
    conn.close()

    stats = {
        'total_docs': total_docs,
        'queries_today': queries_today,
        'avg_response_time': avg_response_time
    }
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
        if file.filename == '':
            flash('No selected file', 'danger')
            return redirect(request.url)
        if file and allowed_file(file.filename):
            filename = file.filename
            file_bytes = file.read()
            filesize = len(file_bytes)
            filetype = filename.rsplit('.', 1)[1].lower()
            upload_time = datetime.now()
            
            file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            with open(file_path, 'wb') as f:
                f.write(file_bytes)
            
            # Using 1 as a placeholder for admin user ID
            conn.execute('INSERT INTO documents (filename, filetype, filesize, upload_timestamp, uploaded_by) VALUES (?, ?, ?, ?, ?)',
                         (filename, filetype, filesize, upload_time.isoformat(), 1))
            conn.commit()
            flash('Document uploaded successfully!', 'success')
            return redirect(url_for('admin_documents'))
        else:
            flash('Invalid file type. Only PDF and DOCX are allowed.', 'danger')
    
    documents = conn.execute('SELECT filename, filetype, filesize, upload_timestamp FROM documents ORDER BY upload_timestamp DESC').fetchall()
    conn.close()
    return render_template('admin_documents.html', documents=documents)


@app.route('/admin/analytics')
def admin_analytics():
    conn = get_db_connection()
    
    # Fetch all interactions for the log table
    # Using .timestamp, .user_query etc. is possible because of conn.row_factory = sqlite3.Row
    interactions = conn.execute('SELECT timestamp, user_query, feedback_score, feedback_comment, response_time_seconds FROM interactions ORDER BY timestamp DESC').fetchall()
    
    # --- UPDATED ANALYTICS LOGIC ---
    
    # Feedback counts
    liked_count = conn.execute('SELECT COUNT(*) FROM interactions WHERE feedback_score = 1').fetchone()[0]
    disliked_count = conn.execute('SELECT COUNT(*) FROM interactions WHERE feedback_score = -1').fetchone()[0]
    total_feedback = liked_count + disliked_count
    no_rating_count = conn.execute('SELECT COUNT(*) FROM interactions').fetchone()[0] - total_feedback

    feedback_counts = {
        'liked': liked_count,
        'disliked': disliked_count,
        'no_rating': no_rating_count,
    }

    # Response time stats
    timing_data = conn.execute('SELECT AVG(response_time_seconds), MIN(response_time_seconds), MAX(response_time_seconds) FROM interactions WHERE response_time_seconds IS NOT NULL').fetchone()
    
    analytics_data = {
        'feedback_counts': feedback_counts,
        'avg_response_time': timing_data[0] or 0,
        'min_response_time': timing_data[1] or 0,
        'max_response_time': timing_data[2] or 0,
    }
    
    conn.close()
    return render_template('admin_analytics.html', interactions=interactions, analytics=analytics_data)

@app.route('/admin/settings')
def admin_settings():
    conn = get_db_connection()
    users = conn.execute('SELECT id, username, password, role FROM users').fetchall()
    conn.close()
    db_info = {'name': 'SQLite', 'model': 'phi3:mini'} # Placeholder info
    return render_template('admin_settings.html', users=users, db_info=db_info)

# --- Client Routes ---
@app.route('/client/dashboard')
def client_dashboard():
    return render_template('client_dashboard.html')
    
@app.route('/client/api_key', methods=['GET', 'POST'])
def client_api_key():
    conn = get_db_connection()
    # Assuming client_id is 2 for demonstration
    client_id_to_use = 2 

    if request.method == 'POST':
        purpose = request.form['purpose']
        api_key = str(uuid.uuid4()) # More secure key
        conn.execute('INSERT INTO api_keys (client_id, api_key, purpose, issuance_timestamp) VALUES (?, ?, ?, ?)',
                     (client_id_to_use, api_key, purpose, datetime.now().isoformat()))
        conn.commit()
        flash(f'New API Key generated for "{purpose}"!', 'success')
        return redirect(url_for('client_api_key'))
    
    api_keys = conn.execute('SELECT * FROM api_keys WHERE client_id = ?', (client_id_to_use,)).fetchall()
    conn.close()
    return render_template('client_api_key.html', api_keys=api_keys)

# --- Chat and Feedback Routes ---

@app.route('/chat', methods=['GET', 'POST'])
def handle_chat():
    if request.method == 'GET':
        return render_template('chat.html')

    # Handle POST request
    query = request.form.get('query')
    url = request.form.get('url')
    document_content = ""
    context_source = "general knowledge"

    if 'document' in request.files and request.files['document'].filename != '':
        file = request.files['document']
        if file and allowed_file(file.filename):
            try:
                context_source = f"the uploaded document '{file.filename}'"
                if file.filename.lower().endswith('.pdf'):
                    document_content = extract_text_from_pdf(file.stream)
                elif file.filename.lower().endswith('.docx'):
                    document_content = extract_text_from_docx(file.stream)
            except Exception as e:
                traceback.print_exc()
                return jsonify({'error': f'Error processing file: {str(e)}'}), 500
        else:
            return jsonify({'error': 'Invalid file type. Please upload PDF or DOCX.'}), 400
    elif url:
        context_source = f"the content from the current page ({url.split('?')[0]})"
        document_content = extract_text_from_url(url)
        if not document_content:
            return jsonify({'error': 'Could not retrieve or parse content from the provided URL.'}), 400

    if not query:
        return jsonify({'error': 'Query cannot be empty.'}), 400

    try:
        start_time = time.time()
        
        # Fixed prompting logic
        if document_content:
            # Clean the document content and limit its size
            clean_content = document_content.strip()[:6000]  # Limit to prevent token overflow
            
            system_prompt = """You are a helpful AI assistant that analyzes documents and answers questions based on their content.

Instructions:
- Answer the user's question using ONLY the information provided in the document
- If the answer is not in the document, say "I cannot find this information in the provided document"
- Be concise and accurate
- Use simple markdown formatting for readability
- Do not provide legal advice"""

            user_message = f"""Based on the document content below, please answer this question: "{query}"

Document content:
{clean_content}

Question: {query}"""
        else:
            # General knowledge path
            system_prompt = """You are a helpful AI assistant that explains data privacy and policy concepts in simple terms.
            
Instructions:
- Provide clear, concise explanations
- Do not give legal advice
- Use simple markdown formatting
- Keep responses practical and helpful"""
            
            user_message = f"Please explain: {query}"

        response = ollama.chat(
            model='phi3:mini',
            messages=[
                {'role': 'system', 'content': system_prompt},
                {'role': 'user', 'content': user_message},
            ],
        )
        
        end_time = time.time()
        duration = end_time - start_time
        
        ai_response_text = response['message']['content']
        html_response = markdown.markdown(ai_response_text)
        response_id = str(uuid.uuid4())

        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute(
                "INSERT INTO interactions (user_query, ai_response, timestamp, response_id, response_time_seconds) VALUES (?, ?, ?, ?, ?)",
                (query, ai_response_text, datetime.now().isoformat(), response_id, duration)
            )
            conn.commit()

        conn_glossary = get_db_connection()
        glossary_terms = conn_glossary.execute('SELECT term, definition FROM glossary').fetchall()
        conn_glossary.close()
        
        glossary_dict = {term['term']: term['definition'] for term in glossary_terms}

        return jsonify({
            'response': html_response,
            'response_id': response_id,
            'duration': f"{duration:.2f}",
            'glossary': glossary_dict
        })

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': f'An unexpected error occurred: {e}'}), 500

@app.route('/feedback', methods=['POST'])
def handle_feedback():
    try:
        score_str = request.form.get('score')
        response_id = request.form.get('response_id')

        if not score_str or not response_id:
            return jsonify({'error': 'Score and response ID are required.'}), 400
        
        score = int(score_str) # score will be 1 for up, -1 for down
        comment = "Liked" if score == 1 else "Disliked"

        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute(
                "UPDATE interactions SET feedback_score = ?, feedback_comment = ? WHERE response_id = ?",
                (score, comment, response_id)
            )
            conn.commit()

            if c.rowcount == 0:
                return jsonify({'error': 'Invalid response ID.'}), 404

        return jsonify({'status': 'success', 'message': 'Feedback received successfully!'})
    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'An internal server error occurred.'}), 500

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)
    
    
@app.route('/admin/glossary', methods=['GET', 'POST'])
def admin_glossary():
    conn = get_db_connection()
    if request.method == 'POST':
        term = request.form['term']
        definition = request.form['definition']
        if term and definition:
            try:
                conn.execute('INSERT INTO glossary (term, definition) VALUES (?, ?)', (term, definition))
                conn.commit()
                flash(f'Term "{term}" added successfully!', 'success')
            except sqlite3.IntegrityError:
                flash(f'Term "{term}" already exists.', 'danger')
        return redirect(url_for('admin_glossary'))

    glossary_terms = conn.execute('SELECT * FROM glossary ORDER BY term').fetchall()
    conn.close()
    return render_template('admin_glossary.html', glossary_terms=glossary_terms)

@app.route('/admin/glossary/delete/<int:term_id>', methods=['GET']) # Using GET for simplicity, POST is better
def admin_delete_term(term_id):
    conn = get_db_connection()
    conn.execute('DELETE FROM glossary WHERE id = ?', (term_id,))
    conn.commit()
    conn.close()
    flash('Term deleted successfully.', 'success')
    return redirect(url_for('admin_glossary'))
    
if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)