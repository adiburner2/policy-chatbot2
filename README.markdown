# Policy Insight Chatbot

A Flask-based web application for the Policy Insight Chatbot, designed to simplify legal documents for users. Developed for the Application Development and Emerging Technologies (ADET) course by Eldrin Adi Kalayag Bentulan.

## Setup Instructions

1. **Clone the Repository**:
   ```bash
   git clone <your-repo-url>
   cd policy-insight-chatbot
   ```

2. **Create a Virtual Environment**:
   ```bash
   python -m venv venv
   source venv/bin/activate  # On Windows: venv\Scripts\activate
   ```

3. **Install Dependencies**:
   ```bash
   pip install -r requirements.txt
   ```

4. **Run the Application**:
   ```bash
   python index.py
   ```

5. **Access the Application**:
   Open `http://localhost:5000` in your browser.

## Project Structure

- `index.py`: Main Flask application.
- `templates/`: HTML templates for all pages.
- `uploads/`: Directory for uploaded documents.
- `policy_chatbot.db`: SQLite database.
- `requirements.txt`: Python dependencies.

## GitHub Setup

1. Initialize a Git repository:
   ```bash
   git init
   git add .
   git commit -m "Initial commit"
   ```

2. Create a repository on GitHub and push:
   ```bash
   git remote add origin <your-repo-url>
   git push -u origin main
   ```

## Next Steps

- Integrate OpenAI API using the `pcb-key` key.
- Implement password reset functionality.
- Add configuration settings page for admins.
- Switch to PostgreSQL for production.
- Set up GitHub Actions for CI/CD.