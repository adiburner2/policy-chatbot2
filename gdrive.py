
import os
import io
from google.oauth2 import service_account
from googleapiclient.discovery import build
from googleapiclient.http import MediaIoBaseDownload, MediaFileUpload

# The ID of the Google Drive folder created and shared.
# From the URL of the folder.
# e.g., if the URL is .../folders/1a2b3c4d5e6f, then that is the ID.
DRIVE_FOLDER_ID = '1dqUclIE-yWsdqnLTIytIsHpO4XWPGbT9' 

# The scopes the app needs to access Google Drive.
SCOPES = ['https://www.googleapis.com/auth/drive']

# Path to the credentials file. From an environment variable.
SERVICE_ACCOUNT_FILE = 'credentials.json'

def get_drive_service():
    """Authenticates and returns a Google Drive service object."""
    if not os.path.exists(SERVICE_ACCOUNT_FILE):
        raise FileNotFoundError(f"Google Drive credentials not found at {SERVICE_ACCOUNT_FILE}. "
                                "Ensure the GOOGLE_CREDENTIALS environment variable is set.")

    creds = service_account.Credentials.from_service_account_file(
        SERVICE_ACCOUNT_FILE, scopes=SCOPES)
    service = build('drive', 'v3', credentials=creds)
    return service

def upload_file(file_stream, filename, mimetype):
    """Uploads a file stream to the specified Google Drive folder."""
    service = get_drive_service()
    media = MediaFileUpload(filename, mimetype=mimetype, resumable=True)
    file_metadata = {'name': filename, 'parents': [DRIVE_FOLDER_ID]}
    
    # Save the stream to a temporary file to upload it
    with open(filename, 'wb') as f:
        f.write(file_stream.read())

    file = service.files().create(
        body=file_metadata,
        media_body=media,
        fields='id'
    ).execute()
    
    # Clean up the temporary file
    os.remove(filename)
    
    return file.get('id')

def download_file(file_id):
    """Downloads a file's content from Google Drive by its ID."""
    service = get_drive_service()
    request = service.files().get_media(fileId=file_id)
    file_stream = io.BytesIO()
    downloader = MediaIoBaseDownload(file_stream, request)
    
    done = False
    while not done:
        status, done = downloader.next_chunk()
        # print(f"Download {int(status.progress() * 100)}%.") # Optional progress
        
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