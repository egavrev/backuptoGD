# SQLite Backup Tool with Encryption/Decryption and Google Drive Integration

This tool allows you to backup your SQLite databases, encrypt them, and upload them to Google Drive.

## Getting Started

These instructions will get you a copy of the project up and running on your local machine for development and testing purposes.

### Prerequisites

You need to have Python installed on your machine. The project also uses the following Python libraries:

- `google-auth`
- `google-auth-oauthlib`
- `google-auth-httplib2`
- `google-api-python-client`
- `pycryptodome`

You can install these libraries using pip:

```shell
pip install --upgrade google-auth google-auth-oauthlib google-auth-httplib2 google-api-python-client pycryptodome
```
## Installing
Clone the repository to your local machine:

```shell
git clone https://github.com/yourusername/SQLite_Backup_Tool.git
```
Navigate to the project directory:
```shell
cd SQLite_Backup_Tool
```

### Run the script:
```shell
python SQLite_Backup_Tool.py
```
### TO DO list
[ ] use secret for encryption
[ ] create function to decrypt file 
[ ] create crontab file to use it on cron