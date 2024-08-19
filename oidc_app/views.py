import logging
import os
import json
import base64
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
# Initialize logging
logging.basicConfig(level=logging.DEBUG,
                    format='%(asctime)s %(levelname)s %(message)s',
                    )



def base64url_decode(input_str):
    logging.info("Decoding base64...")
    padding = '=' * (4 - (len(input_str) % 4))
    return base64.urlsafe_b64decode(input_str + padding)


def load_private_key_from_string(base64_key_str):
    logging.info("Loading private key from base64 key string")
    try:
        # Decode the base64 string
        key_bytes = base64.b64decode(base64_key_str)
        logging.info("*****PK bytes*****")
        logging.info(key_bytes)
        jwk_ = json.loads(key_bytes)


        # Decode the base64url components
        n = int.from_bytes(base64url_decode(jwk_['n']), 'big')
        e = int.from_bytes(base64url_decode(jwk_['e']), 'big')
        d = int.from_bytes(base64url_decode(jwk_['d']), 'big')

        # If your JWK includes p, q, dp, dq, and qi, include them here
        p = int.from_bytes(base64url_decode(jwk_['p']), 'big') if 'p' in jwk_ else None
        q = int.from_bytes(base64url_decode(jwk_['q']), 'big') if 'q' in jwk_ else None
        dmp1 = int.from_bytes(base64url_decode(jwk_['dp']), 'big') if 'dp' in jwk_ else None
        dmq1 = int.from_bytes(base64url_decode(jwk_['dq']), 'big') if 'dq' in jwk_ else None
        iqmp = int.from_bytes(base64url_decode(jwk_['qi']), 'big') if 'qi' in jwk_ else None

        # Create the public numbers for the key
        public_numbers = rsa.RSAPublicNumbers(e, n)

        # Create the private numbers for the key (with or without primes, depending on what you have)
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

        # Generate the private key object
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

    # Generate the signed JWT
    signed_jwt = jwt.encode(payload, private_key, algorithm=ALGORITHM, headers=header)
    logging.info("Signed JWT generated.")
    return signed_jwt


def home(request):

    auth_url = f"{AUTHORIZATION_ENDPOINT}?response_type=code&client_id={CLIENT_ID}&redirect_uri={REDIRECT_URI}&scope=openid profile email&acr_values=mosip:idp:acr:password"
    return render(request, 'oidc_app/home.html', {'auth_url': auth_url})


@csrf_exempt
def callback(request):
    if request.method == "GET":
        # Retrieve the 'code' from the query parameters
        code = request.GET.get('code')
        if not code:
            return JsonResponse({"error": "Authorization code not provided"}, status=400)

        # Generate signed JWT as client_assertion
        client_id = CLIENT_ID
        signed_jwt = generate_signed_jwt(client_id)

        # Define the token endpoint URL
        token_url = TOKEN_ENDPOINT

        # Prepare the payload as URL encoded data
        payload = {
            'grant_type': 'authorization_code',
            'code': code,
            'redirect_uri': REDIRECT_URI,
            'client_id': client_id,
            'client_assertion_type': CLIENT_ASSERTION_TYPE,
            'client_assertion': signed_jwt,
            'code_verifier': 'dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk'
        }

        # Send the token request
        headers = {'Content-Type': 'application/x-www-form-urlencoded'}
        try:
            # Request access token
            response = requests.post(token_url, data=payload, headers=headers)

            if response.status_code == 200:
                # Parse the access token from the response
                token_data = response.json()
                access_token = token_data.get('access_token')
                logging.info(f"Access token: {access_token}")
                userinfo_url = USERINFO_ENDPOINT

                # Send request to the /userinfo endpoint with Bearer token
                userinfo_headers = {
                    'Authorization': f'Bearer {access_token}'
                }
                userinfo_response = requests.get(userinfo_url, headers=userinfo_headers)
                # print(f"User info returned: {userinfo_response.content}")
                if userinfo_response.status_code == 200:
                    user_info_response = userinfo_response.text
                    try:
                        # Decode the JWT without verification (use verify=True if needed)
                        decoded_user_info = jwt.decode(user_info_response, options={"verify_signature": False}, algorithms="RS256")
                        name = decoded_user_info.get('name', 'N/A')
                        email = decoded_user_info.get('email', 'N/A')
                        sub = decoded_user_info.get('sub', 'N/A')
                        picture = decoded_user_info.get('picture', '')

                        # Pass the user info to the template for rendering
                        context = {
                            'name': name,
                            'email': email,
                            'sub': sub,
                            'picture': picture,
                            'user_info': decoded_user_info,
                        }
                        logging.info("User info decode successful!")
                        return render(request, 'oidc_app/callback.html', context)
                    except Exception as e:
                        return JsonResponse({"error": f"Failed to decode JWT: {str(e)}"}, status=500)

        except Exception as e:
            logging.error(f"Exception occurred {e}")


def userinfo(request):
    access_token = request.session.get('access_token')

    if not access_token:
        return redirect('home')

    userinfo_response = requests.get(
        USERINFO_ENDPOINT,
        headers={'Authorization': f'Bearer {access_token}'}
    )

    if userinfo_response.status_code == 200:
        userinfo_data = userinfo_response.json()
        return render(request, 'oidc_app/userinfo.html', {'userinfo': userinfo_data})
    else:
        return JsonResponse({'error': 'Failed to fetch user info'}, status=userinfo_response.status_code)
