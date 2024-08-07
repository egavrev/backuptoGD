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
#### TO DO list
- [X] use secret for encryption
- [X] add refresh tocken option for refresh_token updates to generate new token file.
- [X] create function to decrypt file 
- [ ] add to Readme.md details on how do you obtain token file.
- [ ] bug issues with % char at end of decrypted file
- [ ] refactor to clean code
- [ ] create crontab file to use it on cron
