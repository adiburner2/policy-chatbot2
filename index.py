from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
import os
from datetime import datetime
import pdfplumber
from bs4 import BeautifulSoup
import requests
from huggingface_hub import InferenceClient

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')
DATABASE = 'policy_chatbot.db'

# Initialize Hugging Face client
hf_client = InferenceClient(token=os.getenv('HF_API_TOKEN', 'your-hf-api-token'))

def init_db():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('''CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            role TEXT NOT NULL,
            login_timestamp DATETIME,
            failed_attempts INTEGER DEFAULT 0
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS documents (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            filename TEXT NOT NULL,
            filetype TEXT NOT NULL,
            filesize INTEGER NOT NULL,
            upload_timestamp DATETIME,
            uploaded_by INTEGER,
            FOREIGN KEY(uploaded_by) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS api_keys (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            client_id INTEGER,
            api_key TEXT NOT NULL,
            purpose TEXT,
            issuance_timestamp DATETIME,
            FOREIGN KEY(client_id) REFERENCES users(id)
        )''')
        c.execute('''CREATE TABLE IF NOT EXISTS interactions (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            user_query TEXT,
            ai_response TEXT,
            timestamp DATETIME,
            feedback_score INTEGER,
            feedback_comment TEXT,
            response_id TEXT
        )''')
        conn.commit()

@app.route('/')
def home():
    return render_template('home.html')

def hash_password(password):
    """Simple password hashing (in production, use bcrypt or similar)"""
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        hashed_password = hash_password(password)
        
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, hashed_password))
            user = c.fetchone()
            if not user:
                c.execute('SELECT * FROM users WHERE username = ? AND password = ?', (username, password))
                user = c.fetchone()
                if user:
                    c.execute('UPDATE users SET password = ? WHERE id = ?', (hashed_password, user[0]))
                    conn.commit()
            
            if user:
                c.execute('UPDATE users SET login_timestamp = ? WHERE id = ?', (datetime.now(), user[0]))
                conn.commit()
                flash(f'Welcome, {username}!', 'success')
                if user[3] == 'admin':
                    return redirect(url_for('admin_dashboard'))
                elif user[3] == 'client':
                    return redirect(url_for('client_dashboard'))
            else:
                c.execute('UPDATE users SET failed_attempts = failed_attempts + 1 WHERE username = ?', (username,))
                conn.commit()
                flash('Invalid credentials', 'danger')
        return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/admin/dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')

@app.route('/admin/upload', methods=['GET', 'POST'])
def admin_upload():
    if request.method == 'POST':
        file = request.files['document']
        if file and file.filename.endswith(('.pdf', '.docx')):
            filesize = len(file.read())
            file.seek(0)
            filename = file.filename
            filetype = filename.split('.')[-1]
            upload_time = datetime.now()
            os.makedirs('uploads', exist_ok=True)
            file.save(os.path.join('uploads', filename))
            with sqlite3.connect(DATABASE) as conn:
                c = conn.cursor()
                c.execute('INSERT INTO documents (filename, filetype, filesize, upload_timestamp, uploaded_by) VALUES (?, ?, ?, ?, ?)',
                         (filename, filetype, filesize, upload_time, 1))
                conn.commit()
            flash('Document uploaded successfully')
        else:
            flash('Invalid file type')
        return redirect(url_for('admin_upload'))
    return render_template('admin_upload.html')

@app.route('/admin/documents')
def admin_documents():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('SELECT filename, filetype, filesize, upload_timestamp FROM documents')
        documents = c.fetchall()
    return render_template('admin_documents.html', documents=documents)

@app.route('/admin/analytics')
def admin_analytics():
    with sqlite3.connect(DATABASE) as conn:
        c = conn.cursor()
        c.execute('SELECT user_query, ai_response, feedback_score, feedback_comment FROM interactions')
        interactions = c.fetchall()
    return render_template('admin_analytics.html', interactions=interactions)

@app.route('/client/dashboard')
def client_dashboard():
    return render_template('client_dashboard.html')

@app.route('/client/api_key', methods=['GET', 'POST'])
def client_api_key():
    if request.method == 'POST':
        purpose = request.form['purpose']
        api_key = os.urandom(16).hex()
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('INSERT INTO api_keys (client_id, api_key, purpose, issuance_timestamp) VALUES (?, ?, ?, ?)',
                     (1, api_key, purpose, datetime.now()))
            conn.commit()
        flash(f'API Key generated: {api_key}')
        return redirect(url_for('client_api_key'))
    return render_template('client_api_key.html')

@app.route('/chat', methods=['GET', 'POST'])
def chat():
    if request.method == 'POST':
        query = request.form['query']
        url = request.form.get('url', '')
        
        # Process URL if provided
        web_content = ""
        if url:
            try:
                headers = {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'
                }
                response = requests.get(url, headers=headers, timeout=10)
                response.raise_for_status()
                soup = BeautifulSoup(response.content, 'html.parser')
                for tag in soup(['script', 'style']):
                    tag.decompose()
                web_content = ' '.join(soup.stripped_strings)[:4000]
            except requests.exceptions.HTTPError as e:
                if e.response.status_code == 403:
                    error_msg = (
                        "The website blocked access to its content. Try uploading the policy document directly "
                        "or ask a general question about privacy policies."
                    )
                else:
                    error_msg = f"Error accessing the webpage: {str(e)}"
                print(f"Error fetching URL: {e}")
                return jsonify({'error': error_msg}), 400
            except Exception as e:
                print(f"Error fetching URL: {e}")
                return jsonify({'error': 'Unable to analyze page content. Please try another URL or ask a general question.'}), 400
        
        # Call Hugging Face API
        try:
            system_prompt = (
                "You are a helpful assistant that simplifies complex legal terms and policies. "
                "Given a user query and optional webpage content, provide a clear, concise explanation "
                "in plain language (max 200 words). Identify key legal terms in the response and provide their definitions. "
                "If no webpage content is provided, answer based on general knowledge of privacy policies."
            )
            user_prompt = f"<s>[INST] {system_prompt}\n\nQuery: {query}\n\nWebpage Content: {web_content[:1500] if web_content else 'No webpage content provided.'} [/INST]"

            response_text = hf_client.text_generation(
                prompt=user_prompt,
                model="mistralai/Mixtral-8x7B-Instruct-v0.1",
                max_new_tokens=200,
                temperature=0.7
            )
            
            # Generate response ID
            response_id = f"resp_{datetime.now().strftime('%Y%m%d_%H%M%S')}_{os.urandom(4).hex()}"
            
            # Store interaction
            with sqlite3.connect(DATABASE) as conn:
                c = conn.cursor()
                c.execute('INSERT INTO interactions (user_query, ai_response, timestamp, response_id) VALUES (?, ?, ?, ?)',
                         (query, response_text, datetime.now(), response_id))
                conn.commit()
            
            # Identify and highlight legal terms
            legal_terms = ['policy', 'terms', 'privacy', 'data', 'agreement', 'consent', 'liability', 'jurisdiction']
            highlighted_terms = [term for term in legal_terms if term.lower() in response_text.lower()]
            tooltips = {
                'policy': 'A set of rules or guidelines that govern behavior or procedures',
                'terms': 'Conditions or stipulations that must be agreed to',
                'privacy': 'The right to keep personal information confidential',
                'data': 'Information collected, stored, or processed by a service',
                'agreement': 'A mutual understanding or contract between parties',
                'consent': 'Permission or agreement to allow something to happen',
                'liability': 'Legal responsibility for actions or damages',
                'jurisdiction': 'The authority or area where laws apply'
            }
            
            return jsonify({
                'response': response_text,
                'highlighted_terms': highlighted_terms,
                'tooltips': {term: tooltips.get(term, 'No definition available') for term in highlighted_terms},
                'response_id': response_id
            })
        except Exception as e:
            print(f"Hugging Face API error: {e}")
            return jsonify({'error': 'Unable to generate explanation at this time. Please try again later.'}), 500
    
    return render_template('chat.html')

@app.route('/feedback', methods=['POST'])
def feedback():
    try:
        score = request.form.get('score')
        comment = request.form.get('comment', '')
        response_id = request.form.get('response_id')
        
        if not score or not response_id:
            return jsonify({'error': 'Missing required fields'}), 400
        
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('''UPDATE interactions 
                        SET feedback_score = ?, feedback_comment = ? 
                        WHERE response_id = ?''',
                     (int(score), comment, response_id))
            conn.commit()
            
            if c.rowcount == 0:
                return jsonify({'error': 'Response ID not found'}), 404
        
        return jsonify({'message': 'Feedback submitted successfully'}), 200
    except Exception as e:
        print(f"Feedback error: {e}")
        return jsonify({'error': 'Internal server error'}), 500

if __name__ == '__main__':
    init_db()
    app.run(debug=True)