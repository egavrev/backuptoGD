# Consolidated SQLite Backup Tool with Encryption/Decryption and Google Drive Integration

import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
import googleapiclient.discovery
import google_auth_oauthlib.flow
import google.auth.transport.requests
from googleapiclient.http import MediaFileUpload
import argparse
# Google Drive Integration
# Here we initiate the Google Drive service
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

# Encryption Function
def encrypt_data(data):
    key = get_random_bytes(16) # A 16-byte key
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return (ciphertext, nonce, tag, key)

# Decryption Function
def decrypt_data(ciphertext, nonce, tag, key):
    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    data = cipher.decrypt_and_verify(ciphertext, tag)
    return data

# Function to upload file to Google Drive
def upload_file_to_drive(filepath, filename):
    print(f"Encrypting and uploading file {filename} to Google Drive folder {filepath}")
    
    # Read the file
    with open(filepath, 'rb') as file:
        data = file.read()

    # Encrypt the data
    ciphertext, nonce, tag, key = encrypt_data(data)

    # Write the encrypted data to a new file
    encrypted_filepath = filepath + '.enc'
    with open(encrypted_filepath, 'wb') as file:
        file.write(ciphertext)

    creds = Credentials.from_authorized_user_file('token_new.json', scopes= ['https://www.googleapis.com/auth/drive.file'])
    service = build('drive', 'v3', credentials=creds)
    file_metadata = {'name': filename}
    media = MediaFileUpload(encrypted_filepath, mimetype='application/octet-stream')
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    print(f"File ID: {file.get('id')} - File uploaded successfully")


def get_token():
    # The scopes that you need access to
    SCOPES = ['https://www.googleapis.com/auth/drive.file']

    flow = InstalledAppFlow.from_client_secrets_file(
        'token.json', SCOPES)

    creds = flow.run_local_server(port=0)

    # Save the credentials for the next run
    with open('token_new.json', 'w') as token:
        token.write(creds.to_json())
    #stop program

    

def main():    # Main execution flow
    # Placeholder for tool's operational flow
    print("SQLite Backup Tool with Encryption/Decryption and Google Drive Integration")




    parser = argparse.ArgumentParser()
    parser.add_argument('--file', help='SQLite file to backup or restore. Full path to file must be provided.')
    parser.add_argument('--folder', help='Google Drive folder for backup or restore.')
    parser.add_argument('--credentials', help='OAuth credentials for Google Drive access in JSON format.')
    parser.add_argument('--refresh_token', help='Refresh token for Google Drive access.')
    parser.add_argument('--mode', choices=['backup', 'restore'], help='Select operation mode: backup for uploading and encrypting file to Google Drive, restore for downloading and decrypting file from Google Drive.')
    args = parser.parse_args()
    if args.mode.lower() == 'backup':
        upload_file_to_drive(args.file, args.folder)
    elif args.mode.lower() == 'restore':
        download_and_decrypt_file(args.file, args.folder, args.credentials)
    elif args.mode.lower() == 'refresh_token':
        download_and_decrypt_file(args.file, args.folder, args.credentials)





if __name__ == "__main__":
    main()