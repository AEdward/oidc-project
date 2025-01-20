import logging
import os
import json
import base64
import hashlib
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from django.views.decorators.csrf import csrf_exempt
import jwt
import requests
from django.shortcuts import render, redirect
from django.http import JsonResponse, HttpResponse
from datetime import datetime, timedelta
from jose import JWTError
from jwcrypto import jwk, jwe
from jwcrypto.jwe import InvalidJWEData, JWE
from dotenv import load_dotenv

load_dotenv()

CLIENT_ID = os.environ.get('CLIENT_ID')
REDIRECT_URI = os.environ.get('REDIRECT_URI')
AUTHORIZATION_ENDPOINT = os.environ.get('AUTHORIZATION_ENDPOINT')
TOKEN_ENDPOINT = os.environ.get('TOKEN_ENDPOINT')
USERINFO_ENDPOINT = os.environ.get('USERINFO_ENDPOINT')
PRIVATE_KEY = os.environ.get('PRIVATE_KEY')
EXPIRATION_TIME = timedelta(minutes=15)
ALGORITHM = os.environ.get('ALGORITHM')
CLIENT_ASSERTION_TYPE = os.environ.get('CLIENT_ASSERTION_TYPE')

# PKCE variables (to be used across methods)
CODE_VERIFIER = None
CODE_CHALLENGE = None

# Initialize logging
logging.basicConfig(
    level=logging.DEBUG,
    format='%(asctime)s %(levelname)s %(message)s',
)

# Helper to generate PKCE
def generate_pkce():
    global CODE_VERIFIER, CODE_CHALLENGE
    CODE_VERIFIER = base64.urlsafe_b64encode(os.urandom(32)).rstrip(b'=').decode('utf-8')
    CODE_CHALLENGE = base64.urlsafe_b64encode(
        hashlib.sha256(CODE_VERIFIER.encode('utf-8')).digest()
    ).rstrip(b'=').decode('utf-8')

def base64url_decode(input_str):
    logging.info("Decoding base64...")
    padding = '=' * (4 - (len(input_str) % 4))
    return base64.urlsafe_b64decode(input_str + padding)

def load_private_key_from_string(base64_key_str):
    logging.info("Loading private key from base64 key string")
    try:
        # Decode the base64 string
        key_bytes = base64.b64decode(base64_key_str)
        jwk_ = json.loads(key_bytes)

        # Decode the base64url components
        n = int.from_bytes(base64url_decode(jwk_['n']), 'big')
        e = int.from_bytes(base64url_decode(jwk_['e']), 'big')
        d = int.from_bytes(base64url_decode(jwk_['d']), 'big')

        p = int.from_bytes(base64url_decode(jwk_['p']), 'big') if 'p' in jwk_ else None
        q = int.from_bytes(base64url_decode(jwk_['q']), 'big') if 'q' in jwk_ else None
        dmp1 = int.from_bytes(base64url_decode(jwk_['dp']), 'big') if 'dp' in jwk_ else None
        dmq1 = int.from_bytes(base64url_decode(jwk_['dq']), 'big') if 'dq' in jwk_ else None
        iqmp = int.from_bytes(base64url_decode(jwk_['qi']), 'big') if 'qi' in jwk_ else None

        public_numbers = rsa.RSAPublicNumbers(e, n)

        if p and q and dmp1 and dmq1 and iqmp:
            private_numbers = rsa.RSAPrivateNumbers(
                p=p,
                q=q,
                d=d,
                dmp1=dmp1,
                dmq1=dmq1,
                iqmp=iqmp,
                public_numbers=public_numbers
            )
        else:
            private_numbers = rsa.RSAPrivateNumbers(
                p=None,
                q=None,
                d=d,
                dmp1=None,
                dmq1=None,
                iqmp=None,
                public_numbers=public_numbers
            )

        private_key = private_numbers.private_key(default_backend())
        logging.info("Private Key Loaded Successfully")
        return private_key

    except Exception as e:
        logging.error(f"Failed to load private key: {e}")
        raise

def generate_signed_jwt(client_id):
    logging.info("Generating signed JWT ...")
    header = {
        "alg": ALGORITHM,
        "typ": "JWT",
    }

    payload = {
        "iss": client_id,
        "sub": client_id,
        "aud": TOKEN_ENDPOINT,
        "exp": datetime.utcnow() + EXPIRATION_TIME,
        "iat": datetime.utcnow(),
    }

    private_key = load_private_key_from_string(PRIVATE_KEY)

    signed_jwt = jwt.encode(payload, private_key, algorithm=ALGORITHM, headers=header)
    logging.info("Signed JWT generated.")
    return signed_jwt

def home(request):
    global CODE_VERIFIER, CODE_CHALLENGE
    generate_pkce()  # Generate PKCE before creating the auth URL
    auth_url = (
        f"{AUTHORIZATION_ENDPOINT}?"
        f"response_type=code&"
        f"client_id={CLIENT_ID}&"
        f"redirect_uri={REDIRECT_URI}&"
        f"scope=openid profile email&"
        f"acr_values=mosip:idp:acr:password&"
        f"code_challenge={CODE_CHALLENGE}&"
        f"code_challenge_method=S256"
    )
    return render(request, 'oidc_app/home.html', {'auth_url': auth_url})


@csrf_exempt
def callback(request):
    if request.method == "GET":
        code = request.GET.get('code')
        if not code:
            return JsonResponse({"error": "Authorization code not provided"}, status=400)

        signed_jwt = generate_signed_jwt(CLIENT_ID)
        token_url = TOKEN_ENDPOINT

        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': CLIENT_ID,
            'client_assertion_type': CLIENT_ASSERTION_TYPE,
            'client_assertion': signed_jwt,
            'code_verifier': CODE_VERIFIER,
        }

        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        try:
            response = requests.post(token_url, data=payload, headers=headers)

            if response.status_code == 200:
                token_data = response.json()
                access_token = token_data.get('access_token')
                userinfo_url = USERINFO_ENDPOINT
                userinfo_headers = {'Authorization': f'Bearer {access_token}'}
                userinfo_response = requests.get(userinfo_url, headers=userinfo_headers)

                if userinfo_response.status_code == 200:
                    user_info_response = userinfo_response.text
                    try:
                        # Decode the JWT without verification (use verify=True if needed)
                        decoded_user_info = jwt.decode(user_info_response, options={"verify_signature": False}, algorithms="RS256")
                        name = decoded_user_info.get('name', 'N/A')
                        email = decoded_user_info.get('email', 'N/A')
                        sub = decoded_user_info.get('sub', 'N/A')
                        picture = decoded_user_info.get('picture', '')
                        phone = decoded_user_info.get('phone', '')
                        birthdate = decoded_user_info.get('birthdate', '')
                        residence_status = decoded_user_info.get('residenceStatus', '')
                        gender = decoded_user_info.get('gender', ''),
                        address = decoded_user_info.get('address', '')
                        logging.info("------------------------------")
                        logging.info(user_info_response)
                        logging.info("###############################")
                        logging.info(decoded_user_info)
                        logging.info("###############################")



                        # Pass the user info to the template for rendering
                        context = {
                            'name': name,
                            'email': email,
                            'sub': sub,
                            'picture': picture,
                            'phone': phone,
                            'residence_status': residence_status,
                            'birthdate': birthdate,
                            'gender': gender,
                            'address': address,
                        }
                        # logging.info("Not decoded user info:" + user_info_response)
                        logging.info("User info decode successful!")
                        return render(request, 'oidc_app/callback.html', context)

                    except Exception as e:
                        return JsonResponse({"error": f"Failed to decode JWT: {str(e)}"}, status=500)
            else:
                logging.info(f"Error occurred with status code: {response.status_code} and response is: {response.content}")

        except Exception as e:
            logging.error(f"Exception occurred -- {e}")

