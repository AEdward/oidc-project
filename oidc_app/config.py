import os
from datetime import timedelta

from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.environ.get('CLIENT_ID')
REDIRECT_URI = os.environ.get('REDIRECT_URI')
AUTHORIZATION_ENDPOINT = os.environ.get('AUTHORIZATION_ENDPOINT')
TOKEN_ENDPOINT = os.environ.get('TOKEN_ENDPOINT')
USERINFO_ENDPOINT = os.environ.get('USERINFO_ENDPOINT')
PRIVATE_KEY = os.environ.get('PRIVATE_KEY')
# PRIVATE_KEY_USER_INFO = os.environ.get('PRIVATE_KEY_USER_INFO')
EXPIRATION_TIME = timedelta(minutes=15)
ALGORITHM = os.environ.get('ALGORITHM')
CLIENT_ASSERTION_TYPE = os.environ.get('CLIENT_ASSERTION_TYPE')