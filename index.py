# --- START OF FILE index.py ---

from flask import Flask, render_template, request, redirect, url_for, flash, jsonify
import sqlite3
import os
from datetime import datetime
import pdfplumber
from bs4 import BeautifulSoup
import requests
import ollama  # Make sure this is imported
import uuid    # To generate unique IDs for responses
import traceback # For better error logging
import markdown  # To convert AI response to HTML
import time

app = Flask(__name__)
app.secret_key = os.getenv('FLASK_SECRET_KEY', 'your-secret-key')
DATABASE = 'policy_chatbot.db'


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
        # --- Add test users if not present ---
        c.execute("SELECT COUNT(*) FROM users")
        if c.fetchone()[0] == 0:
            c.execute(
                "INSERT INTO users (username, password, role, login_timestamp, failed_attempts) VALUES (?, ?, ?, ?, ?)",
                ('admin', hash_password('admin123'), 'admin', datetime.now(), 0)
            )
            c.execute(
                "INSERT INTO users (username, password, role, login_timestamp, failed_attempts) VALUES (?, ?, ?, ?, ?)",
                ('client', hash_password('client123'), 'client', datetime.now(), 0)
            )
            conn.commit()
        conn.commit()

@app.route('/')
def home():
    return render_template('home.html')

def hash_password(password):
    import hashlib
    return hashlib.sha256(password.encode()).hexdigest()


@app.route('/samplepolicy')
def sample_policy():
    return render_template('samplepolicy.html')

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


# --- COMPLETED CHAT ROUTE (Using gemma3:4b) ---
@app.route('/chat', methods=['GET', 'POST'])
def handle_chat():
    if request.method == 'GET':
        return render_template('chat.html')

    if request.method == 'POST':
        query = request.form.get('query')
        url = request.form.get('url')  # Get the URL from the form

        if not query:
            return jsonify({'error': 'Query cannot be empty.'}), 400

        try:
            page_context = ""
            if url:
                try:
                    # Fetch the content from the URL
                    headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.36'}
                    page_response = requests.get(url, headers=headers, timeout=10)
                    page_response.raise_for_status()  # Raise an exception for bad status codes (4xx or 5xx)

                    # Parse the HTML and extract text
                    soup = BeautifulSoup(page_response.text, 'html.parser')
                    # Get all text from the body, which is usually where the main content is
                    if soup.body:
                        page_context = soup.body.get_text(separator=' ', strip=True)
                    else:
                        page_context = soup.get_text(separator=' ', strip=True)
                    
                    if not page_context:
                         return jsonify({'error': f"Could not extract any text from the URL: {url}"}), 400

                except requests.RequestException as e:
                    return jsonify({'error': f"Failed to fetch content from URL: {e}"}), 400
            
            # Construct the prompt for the AI
            system_prompt = "You are 'Policy Insight', a helpful AI assistant. Your goal is to simplify complex legal documents for users."
            
            # If context is provided, instruct the AI to use it
            if page_context:
                user_message_content = f"""
                Here is the content of the policy from the provided URL:
                ---
                {page_context}
                ---
                Based ONLY on the text above, please answer the following question: {query}
                
                If the answer is not in the text, say 'I could not find that information in the provided document.'
                """
                system_prompt += " Answer the user's question based strictly on the provided context."
            else:
                # If no URL, handle as a general question
                user_message_content = query
                system_prompt += " Your task is to answer general questions about privacy policies, terms of service, and data protection."


            start_time = time.time()
            response = ollama.chat(
                model='phi3:mini',
                messages=[
                    {'role': 'system', 'content': system_prompt},
                    {'role': 'user', 'content': user_message_content},
                ]
            )
            end_time = time.time()
            duration = end_time - start_time

            ai_response_text = response['message']['content']
            html_response = markdown.markdown(ai_response_text)
            response_id = str(uuid.uuid4())

            with sqlite3.connect(DATABASE) as conn:
                c = conn.cursor()
                c.execute(
                    "INSERT INTO interactions (user_query, ai_response, timestamp, response_id) VALUES (?, ?, ?, ?)",
                    (query, ai_response_text, datetime.now(), response_id)
                )
                conn.commit()

            return jsonify({
                'response': html_response,
                'response_id': response_id,
                'duration': f"{duration:.2f}"
            })

        except Exception as e:
            traceback.print_exc()
            return jsonify({'error': f'An unexpected error occurred: {e}'}), 500

@app.route('/feedback', methods=['POST'])
def handle_feedback():
    try:
        score = request.form.get('score')
        comment = request.form.get('comment')
        response_id = request.form.get('response_id')

        if not score or not response_id:
            return jsonify({'error': 'Score and response ID are required.'}), 400

        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute(
                "UPDATE interactions SET feedback_score = ?, feedback_comment = ? WHERE response_id = ?",
                (score, comment, response_id)
            )
            conn.commit()
            if c.rowcount == 0:
                return jsonify({'error': 'Invalid response ID.'}), 404
        return jsonify({'message': 'Feedback received successfully!'})

    except Exception as e:
        traceback.print_exc()
        return jsonify({'error': 'An internal server error occurred.'}), 500

if __name__ == "__main__":
    init_db()
    app.run(debug=True, port=5000)