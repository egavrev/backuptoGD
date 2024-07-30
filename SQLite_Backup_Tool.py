# Consolidated SQLite Backup Tool with Encryption/Decryption and Google Drive Integration

import json
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from Crypto.Protocol.KDF import PBKDF2
from Crypto.Hash import SHA256
import googleapiclient.discovery
import google_auth_oauthlib.flow
import google.auth.transport.requests
from googleapiclient.http import MediaFileUpload
import argparse
import os
import base64   


# Google Drive Integration
# Here we initiate the Google Drive service
from googleapiclient.discovery import build
from google.oauth2.credentials import Credentials
from google_auth_oauthlib.flow import InstalledAppFlow

# Function to derive a key from a password
def derive_key(password, salt, key_length=16):
    return PBKDF2(password, salt, dkLen=key_length, count=1000000, hmac_hash_module=SHA256)


# Encryption Function
def encrypt_data(data, password):
    salt = os.urandom(16)  # Generate a random salt
    key = derive_key(password, salt)
    cipher = AES.new(key, AES.MODE_EAX)
    nonce = cipher.nonce
    ciphertext, tag = cipher.encrypt_and_digest(data)
    return ciphertext


# Decryption Function
def decrypt_data(ciphertext, nonce, tag, password, salt):
    # Derive the key from the password and salt
    key = derive_key(password, salt)
    
    # Debug prints to check the values
    print(f"Ciphertext: {base64.b64encode(ciphertext).decode()}")
    print(f"Nonce: {base64.b64encode(nonce).decode()}")
    print(f"Tag: {base64.b64encode(tag).decode()}")
    print(f"AES Key: {base64.b64encode(key).decode()}")

    cipher = AES.new(key, AES.MODE_EAX, nonce=nonce)
    try:
        data = cipher.decrypt_and_verify(ciphertext, tag)
        return data
    except ValueError as e:
        print("Decryption failed: ", e)
        raise

# Function to upload file to Google Drive
def upload_file_to_drive(local_file, gd_file, aes_key):
    print(f"Encrypting and uploading file {local_file} to Google Drive folder {gd_file}")
    
    # Read the file
    with open(local_file, 'rb') as file:
        data = file.read()

    # Encrypt the data
    ciphertext = encrypt_data(data, aes_key)

    # Write the encrypted data to a new file
    encrypted_filepath = local_file + '.enc'
    with open(encrypted_filepath, 'wb') as file:
        file.write(ciphertext)

    creds = Credentials.from_authorized_user_file('token.json', scopes= ['https://www.googleapis.com/auth/drive.file'])
    service = build('drive', 'v3', credentials=creds)
    file_metadata = {'name': gd_file}
    media = MediaFileUpload(encrypted_filepath, mimetype='application/octet-stream')
    file = service.files().create(body=file_metadata, media_body=media, fields='id').execute()
    print(f"File ID: {file.get('id')} - File uploaded successfully")


def download_and_decrypt_file(local_file, gd_file, aes_key):
    print(f"Downloading and decrypting file {gd_file} from Google Drive to {local_file}")

    creds = Credentials.from_authorized_user_file('token.json', scopes=['https://www.googleapis.com/auth/drive.file'])
    service = build('drive', 'v3', credentials=creds)

    # Find the file on Google Drive
    results = service.files().list(q=f"name='{gd_file}'", spaces='drive', fields='files(id)').execute()
    items = results.get('files', [])
    if not items:
        print('File not found')
    else:
        file_id = items[0]['id']
        request = service.files().get_media(fileId=file_id)
        fh = open(local_file, 'wb')
        downloader = googleapiclient.http.MediaIoBaseDownload(fh, request)
        done = False
        while done is False:
            status, done = downloader.next_chunk()
            print(f"Download {int(status.progress() * 100)}%")
        fh.close()
        
        # Read the file
        with open(local_file, 'rb') as file:
            data = file.read()
        print(f"Extracted Data: {base64.b64encode(data).decode()}")
        # Extract the salt, nonce, ciphertext, and tag from the data
        salt = data[:16]
        nonce = data[16:32]
        ciphertext = data[32:-16]
        tag = data[-16:]
        # Debug prints to verify extracted values
        print(f"Extracted Salt: {base64.b64encode(salt).decode()}")
        print(f"Extracted Nonce: {base64.b64encode(nonce).decode()}")
        print(f"Extracted Ciphertext: {base64.b64encode(ciphertext).decode()}")
        print(f"Extracted Tag: {base64.b64encode(tag).decode()}")

        
        # Decrypt the data
        decrypted_data = decrypt_data(ciphertext, nonce, tag, aes_key, salt)

        # Write the decrypted data to a new file
        decrypted_filepath = local_file + '.dec'
        with open(decrypted_filepath, 'wb') as file:
            file.write(decrypted_data)

        print(f"File downloaded and decrypted successfully to {decrypted_filepath}")


def get_token():
    # The scopes that you need access to
    SCOPES = ['https://www.googleapis.com/auth/drive.file']

    creds = None
    token_path = './token.json'  # Path to save the new token file
    
    flow = InstalledAppFlow.from_client_secrets_file('token_client.json', SCOPES)
    creds = flow.run_local_server(port=0)
    with open(token_path, 'w') as token:
        token.write(creds.to_json())
    print(f"Refresh token: {creds}")
    return creds

    

def main():    # Main execution flow
    # Placeholder for tool's operational flow
    print("SQLite Backup Tool with Encryption/Decryption and Google Drive Integration")
   
    parser = argparse.ArgumentParser()
    parser.add_argument('--local_file', help='SQLite file to backup or restore. Full path to file must be provided.')
    parser.add_argument('--gd_file', help='Google Drive folder for backup or restore.')
    parser.add_argument('--refresh_token', help='Refresh token for Google Drive access.')
    parser.add_argument('--aes_key', help='AES key for encryption/decryption.')

    parser.add_argument('--mode', choices=['backup', 'restore', 'refresh_token'], help='Select operation mode: backup for uploading and encrypting file to Google Drive, restore for downloading and decrypting file from Google Drive.')
    args = parser.parse_args()
    if args.mode.lower() == 'backup':
        upload_file_to_drive(args.local_file, args.gd_file, args.aes_key)
    elif args.mode.lower() == 'restore':
        download_and_decrypt_file(args.local_file, args.gd_file, args.aes_key)
    elif args.mode.lower() == 'refresh_token':
        get_token()





if __name__ == "__main__":
    main()