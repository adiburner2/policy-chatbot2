import os
from google_auth_oauthlib.flow import Flow

# This is the scope your app needs.
SCOPES = ['https://www.googleapis.com/auth/drive']
# The file you downloaded from Google Cloud Console.
CLIENT_SECRETS_FILE = 'client_secret.json'
# The file where the final token will be stored.
TOKEN_FILE = 'token.json'

def main():
    """Runs the authorization flow and saves the token."""
    if not os.path.exists(CLIENT_SECRETS_FILE):
        print(f"Error: {CLIENT_SECRETS_FILE} not found. Please download it from Google Cloud Console.")
        return

    flow = Flow.from_client_secrets_file(
        CLIENT_SECRETS_FILE,
        scopes=SCOPES,
        redirect_uri='http://localhost:8080'
    )

    # Generate the URL for the user to visit.
    auth_url, _ = flow.authorization_url(prompt='consent')

    print('Please visit this URL to authorize the application:')
    print(auth_url)
    print("\nAfter authorizing, you'll be redirected to a 'localhost' URL.")
    print("Copy the ENTIRE URL from your browser's address bar and paste it here:")

    # Get the full redirect URL from the user.
    code_url = input('Paste the full redirect URL here: ').strip()

    # Exchange the authorization code for a refresh token.
    flow.fetch_token(authorization_response=code_url)

    # Save the credentials for the application to use.
    creds = flow.credentials
    with open(TOKEN_FILE, 'w') as token:
        token.write(creds.to_json())

    print(f"\nSuccess! Credentials saved to {TOKEN_FILE}.")
    print("You now need to Base64 encode this file and add it to your Render environment variables.")

if __name__ == '__main__':
    main()