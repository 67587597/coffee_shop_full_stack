import json
from flask import request, _request_ctx_stack
from functools import wraps
from jose import jwt
from urllib.request import urlopen


AUTH0_DOMAIN = 'dev-nhx1jtvg.us.auth0.com'
ALGORITHMS = ['RS256']
API_AUDIENCE = 'coffee_shop'

## AuthError Exception
'''
AuthError Exception
A standardized way to communicate auth failure modes
'''
class AuthError(Exception):
    def __init__(self, error, status_code):
        self.error = error
        self.status_code = status_code


## Auth Header

'''
@TODO implement get_token_auth_header() method
    it should attempt to get the header from the request
        it should raise an AuthError if no header is present
    it should attempt to split bearer and the token
        it should raise an AuthError if the header is malformed
    return the token part of the header
'''
def get_token_auth_header():
    if 'authorization' not in request.headers:
        raise AuthError({'code': 'authorization_header',
                        'description': 'authorization is missing'
                        }, 401)
    
    auth_header = request.headers['authorization'].split('')

    if auth_header[0].lower() != 'bearer' or len(auth_header) != 2:
            raise AuthError({
            'code': 'invalid_header',
            'description': 'authorization header must be bearer token'
            }, 401)

    return auth_header[1]
    # raise Exception('Not Implemented')

'''
@TODO implement check_permissions(permission, payload) method
    @INPUTS
        permission: string permission (i.e. 'post:drink')
        payload: decoded jwt payload

    it should raise an AuthError if permissions are not included in the payload
        !!NOTE check your RBAC settings in Auth0
    it should raise an AuthError if the requested permission string is not in the payload permissions array
    return true otherwise
'''
def check_permissions(permission, payload):
    if 'permission' not in payload:
         raise AuthError({
            'code': 'invalid_header',
            'description': 'authorization header must be bearer token'
            }, 401)
    if permission not in payload['permission']:
         raise AuthError({
            'code': 'unautorized',
            'description': 'the access is not granted'
            }, 403)
    return True
    # raise Exception('Not Implemented')

'''
@TODO implement verify_decode_jwt(token) method
    @INPUTS
        token: a json web token (string)

    it should be an Auth0 token with key id (kid)
    it should verify the token using Auth0 /.well-known/jwks.json
    it should decode the payload from the token
    it should validate the claims
    return the decoded payload

    !!NOTE urlopen has a common certificate error described here: https://stackoverflow.com/questions/50236117/scraping-ssl-certificate-verify-failed-error-for-http-en-wikipedia-org
'''
def verify_decode_jwt(token):
    # get the puplic key ID
    url = urlopen(f'https://{AUTH0_DOMAIN}/.well-known/jwks.json')
    jwks = json.loads(url.read())

    # unpack the recieved token 
    header_to_verify = jwt.get_unverified_header(token)

    # if kid is not included in the recieved token, raise error
    if 'kid' not in header_to_verify:
        raise AuthError({
            'code': 'Invalid_header',
            'description': 'Invalid header'
            }, 401)
    rsa_key = {}
    # if puplic kid is matched the recieved kid, form the structure of the payload
    if jwks['Keys']['kid'] == header_to_verify['kid']:
        rsa_key = {
            'kty': jwks['Keys']['kty'],
            'kid': jwks['Keys']['kid'],
            'use': jwks['Keys']['use'],
            'n': jwks['Keys']['n'],
            'e': jwks['Keys']['e']
        }
    
    if rsa_key:
        try:
            # decode the token, and raise error if it is not valid
            payload = jwt.decode(
                token,
                rsa_key,
                algorithms=ALGORITHMS,
                audience=API_AUDIENCE,
                issuer='https://' + AUTH0_DOMAIN + '/'
            )
            return payload

        except jwt.ExpiredSignatureError:
            raise AuthError({
            'code': 'expired_Token',
            'description': 'Token Expired'
            }, 401)

        except jwt.JWTClaimsError:
            raise AuthError({
                'code': 'invalid_claims',
                'description': 'invalid claims'
            }, 401)

    raise AuthError({
                'code': 'invalid_header',
                'description': 'invalid header'
            }, 400)

'''
@TODO implement @requires_auth(permission) decorator method
    @INPUTS
        permission: string permission (i.e. 'post:drink')

    it should use the get_token_auth_header method to get the token
    it should use the verify_decode_jwt method to decode the jwt
    it should use the check_permissions method validate claims and check the requested permission
    return the decorator which passes the decoded payload to the decorated method
'''
def requires_auth(permission=''):
    def requires_auth_decorator(f):
        @wraps(f)
        def wrapper(*args, **kwargs):
            token = get_token_auth_header()
            
            try:
                payload = verify_decode_jwt(token)
            except:
                raise AuthError({
                'code': 'invalid token',
                'description': 'Invalid Token'
                }, 401)

            check_permissions(permission, payload)
            return f(payload, *args, **kwargs)

        return wrapper
    return requires_auth_decorator