# --- START of gdrive.py code changes ---

import os
import io
import base64
import json
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow
from google.auth.transport.requests import Request
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaIoBaseUpload

# The ID of the REGULAR Google Drive folder you created in your own account.
DRIVE_FOLDER_ID = '1dqUclIE-yWsdqnLTIytIsHpO4XWPGbT9' 

SCOPES = ['https://www.googleapis.com/auth/drive']

# Temporary file paths on the Render server
CLIENT_SECRET_FILE = 'client_secret.json'
TOKEN_FILE = 'token.json'

def get_drive_service():
    """Authenticates using user credentials (OAuth 2.0) and returns a Google Drive service object."""
    creds = None

    # Decode and write the token.json from environment variable
    if 'GOOGLE_TOKEN_BASE64' in os.environ:
        token_base64 = os.environ['GOOGLE_TOKEN_BASE64']
        token_json_str = base64.b64decode(token_base64).decode('utf-8')
        with open(TOKEN_FILE, 'w') as f:
            f.write(token_json_str)
        creds = Credentials.from_authorized_user_file(TOKEN_FILE, SCOPES)

    # If there are no (valid) credentials available, let it refresh.
    if not creds or not creds.valid:
        if creds and creds.expired and creds.refresh_token:
            # Decode and write the client_secret.json from environment variable
            if 'GOOGLE_CLIENT_SECRET_BASE64' in os.environ:
                secret_base64 = os.environ['GOOGLE_CLIENT_SECRET_BASE64']
                secret_json_str = base64.b64decode(secret_base64).decode('utf-8')
                with open(CLIENT_SECRET_FILE, 'w') as f:
                    f.write(secret_json_str)
                creds.refresh(Request())
            else:
                raise Exception("Cannot refresh token: GOOGLE_CLIENT_SECRET_BASE64 is not set.")
        else:
            # This part should not be reached in production if the setup is correct.
            raise Exception("Could not authenticate. Run authorize_gdrive.py locally first.")
        
        # Save the potentially refreshed credentials back to the file
        with open(TOKEN_FILE, 'w') as token:
            token.write(creds.to_json())

    service = build('drive', 'v3', credentials=creds)
    # Clean up the temp files
    if os.path.exists(CLIENT_SECRET_FILE): os.remove(CLIENT_SECRET_FILE)
    if os.path.exists(TOKEN_FILE): os.remove(TOKEN_FILE)
    return service

def upload_file(file_stream, filename, mimetype):
    """Uploads a file stream to the specified Google Drive folder."""
    service = get_drive_service()
    file_metadata = {'name': filename, 'parents': [DRIVE_FOLDER_ID]}
    media = MediaIoBaseUpload(file_stream, mimetype=mimetype, resumable=True)
    file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id'
    ).execute()
    return file.get('id')

def download_file(file_id):
    """Downloads a file's content from Google Drive by its ID."""
    service = get_drive_service()
    request = service.files().get_media(fileId=file_id)
    file_stream = io.BytesIO()
    downloader = MediaIoBaseDownload(file_stream, request)
    done = False
    while not done:
        _, done = downloader.next_chunk()
    file_stream.seek(0)
    return file_stream

def delete_file(file_id):
    """Permanently deletes a file from Google Drive."""
    try:
        service = get_drive_service()
        service.files().delete(fileId=file_id).execute()
        return True
    except Exception as e:
        print(f"Error deleting file {file_id} from Google Drive: {e}")
        return False
# --- END of gdrive.py code changes ---