#!/usr/bin/env python3
"""
Test User Creation Script for Policy Insight Chatbot
Creates admin and client test users in the database
"""

import sqlite3
import hashlib
from datetime import datetime
import os

DATABASE = 'policy_chatbot.db'

def hash_password(password):
    """Simple password hashing (in production, use bcrypt or similar)"""
    return hashlib.sha256(password.encode()).hexdigest()

def create_test_users():
    """Create test users for admin and client roles"""
    
    # Test users data
    test_users = [
        {
            'username': 'admin',
            'password': 'admin123',
            'role': 'admin',
            'description': 'System Administrator'
        },
        {
            'username': 'testadmin',
            'password': 'testpass',
            'role': 'admin',
            'description': 'Test Administrator Account'
        },
        {
            'username': 'client1',
            'password': 'client123',
            'role': 'client',
            'description': 'Test Client Company 1'
        },
        {
            'username': 'client2',
            'password': 'client456',
            'role': 'client',
            'description': 'Test Client Company 2'
        },
        {
            'username': 'democlient',
            'password': 'demo2024',
            'role': 'client',
            'description': 'Demo Client for Testing'
        },
        {
            'username': 'plainuser',
            'password': 'plain123',
            'role': 'admin',
            'description': 'Plain text password user (for testing compatibility)',
            'use_plain_text': True
        }
    ]
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            
            # Check if users table exists
            c.execute("""SELECT name FROM sqlite_master 
                        WHERE type='table' AND name='users'""")
            if not c.fetchone():
                print("❌ Users table not found. Please run the main application first to initialize the database.")
                return False
            
            print("🔧 Creating test users...")
            print("-" * 50)
            
            created_count = 0
            for user in test_users:
                try:
                    # Check if user already exists
                    c.execute('SELECT username FROM users WHERE username = ?', (user['username'],))
                    if c.fetchone():
                        print(f"⚠️  User '{user['username']}' already exists - skipping")
                        continue
                    
                    # Hash password (in production, use proper password hashing)
                    if user.get('use_plain_text', False):
                        stored_password = user['password']  # Store as plain text
                        print(f"   Using plain text password for compatibility testing")
                    else:
                        stored_password = hash_password(user['password'])  # Store hashed
                    
                    # Insert user
                    c.execute('''INSERT INTO users 
                                (username, password, role, login_timestamp, failed_attempts) 
                                VALUES (?, ?, ?, ?, ?)''',
                             (user['username'], stored_password, user['role'], None, 0))
                    
                    print(f"✅ Created {user['role']} user: {user['username']}")
                    print(f"   Password: {user['password']}")
                    print(f"   Role: {user['role']}")
                    print(f"   Description: {user['description']}")
                    print()
                    
                    created_count += 1
                    
                except sqlite3.IntegrityError as e:
                    print(f"❌ Error creating user '{user['username']}': {e}")
            
            conn.commit()
            
            print("-" * 50)
            print(f"✅ Successfully created {created_count} test users!")
            
            # Display summary
            c.execute('SELECT username, role FROM users ORDER BY role, username')
            all_users = c.fetchall()
            
            print("\n📊 Current users in database:")
            print("-" * 30)
            for username, role in all_users:
                print(f"• {username} ({role})")
            
            return True
            
    except sqlite3.Error as e:
        print(f"❌ Database error: {e}")
        return False
    except Exception as e:
        print(f"❌ Unexpected error: {e}")
        return False

def create_sample_api_keys():
    """Create sample API keys for test clients"""
    
    sample_keys = [
        {
            'client_username': 'client1',
            'purpose': 'Website Integration Testing',
        },
        {
            'client_username': 'client2', 
            'purpose': 'Mobile App Development',
        },
        {
            'client_username': 'democlient',
            'purpose': 'Demo and Evaluation',
        }
    ]
    
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            
            print("\n🔑 Creating sample API keys...")
            print("-" * 50)
            
            for key_info in sample_keys:
                # Get client ID
                c.execute('SELECT id FROM users WHERE username = ? AND role = "client"', 
                         (key_info['client_username'],))
                client = c.fetchone()
                
                if not client:
                    print(f"⚠️  Client '{key_info['client_username']}' not found - skipping API key")
                    continue
                
                client_id = client[0]
                
                # Generate API key
                api_key = os.urandom(16).hex()
                
                # Insert API key
                c.execute('''INSERT INTO api_keys 
                            (client_id, api_key, purpose, issuance_timestamp) 
                            VALUES (?, ?, ?, ?)''',
                         (client_id, api_key, key_info['purpose'], datetime.now()))
                
                print(f"✅ API Key for {key_info['client_username']}")
                print(f"   Key: {api_key}")
                print(f"   Purpose: {key_info['purpose']}")
                print()
            
            conn.commit()
            print("✅ API keys created successfully!")
            
    except Exception as e:
        print(f"❌ Error creating API keys: {e}")

def verify_login(username, password):
    """Verify that a user can login with given credentials"""
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            hashed_password = hash_password(password)
            c.execute('SELECT username, role FROM users WHERE username = ? AND password = ?', 
                     (username, hashed_password))
            user = c.fetchone()
            
            if user:
                print(f"✅ Login verification successful for {username} ({user[1]})")
                return True
            else:
                print(f"❌ Login verification failed for {username}")
                return False
                
    except Exception as e:
        print(f"❌ Error verifying login: {e}")
        return False

def debug_user_passwords():
    """Debug function to check stored passwords in database"""
    try:
        with sqlite3.connect(DATABASE) as conn:
            c = conn.cursor()
            c.execute('SELECT username, password, role FROM users')
            users = c.fetchall()
            
            print("\n🔍 DEBUG: Password storage analysis")
            print("-" * 50)
            
            for username, stored_password, role in users:
                is_likely_hashed = len(stored_password) == 64 and all(c in '0123456789abcdef' for c in stored_password.lower())
                print(f"User: {username} ({role})")
                print(f"  Stored: {stored_password}")
                print(f"  Type: {'Hashed (SHA-256)' if is_likely_hashed else 'Plain text'}")
                
                # Try to verify with common test passwords
                test_passwords = ['admin123', 'client123', 'demo2024', 'testpass', 'client456', 'plain123']
                for test_pass in test_passwords:
                    if stored_password == test_pass:
                        print(f"  ✅ Matches plain text: {test_pass}")
                        break
                    elif stored_password == hash_password(test_pass):
                        print(f"  ✅ Matches hashed: {test_pass}")
                        break
                else:
                    print(f"  ❓ No match found with common passwords")
                print()
                
    except Exception as e:
        print(f"❌ Debug error: {e}")

def main():
    """Main function to create test users and verify setup"""
    
    print("=" * 60)
    print("🚀 Policy Insight Chatbot - Test User Setup")
    print("=" * 60)
    
    # Check if database file exists
    if not os.path.exists(DATABASE):
        print(f"❌ Database file '{DATABASE}' not found.")
        print("   Please run the main Flask application first to initialize the database.")
        return
    
    # Debug existing passwords first
    debug_user_passwords()
    
    # Create test users
    if create_test_users():
        # Create sample API keys
        create_sample_api_keys()
        
        # Debug after creation
        debug_user_passwords()
        
        # Verify some logins
        print("\n🔍 Verifying test user logins...")
        print("-" * 50)
        verify_login('admin', 'admin123')
        verify_login('client1', 'client123')
        verify_login('democlient', 'demo2024')
        verify_login('plainuser', 'plain123')
        
        print("\n" + "=" * 60)
        print("✅ Test user setup completed successfully!")
        print("\n📝 Login Credentials Summary:")
        print("   Admin Users:")
        print("   • admin / admin123")
        print("   • testadmin / testpass")
        print("   • plainuser / plain123 (plain text for testing)")
        print("\n   Client Users:")
        print("   • client1 / client123")
        print("   • client2 / client456") 
        print("   • democlient / demo2024")
        print("=" * 60)
    else:
        print("❌ Test user setup failed!")

if __name__ == '__main__':
    main()