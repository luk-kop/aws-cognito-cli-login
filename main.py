import os
import sys
import logging
import re

import boto3
from botocore.exceptions import ClientError
from pwinput import pwinput
from dotenv import load_dotenv
import segno


logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger()
logging.getLogger('botocore').setLevel(logging.WARNING)

load_dotenv('.env')
COGNITO_URL = os.getenv('COGNITO_URL')
COGNITO_USER_POOL_ID = os.getenv('COGNITO_USER_POOL_ID')
COGNITO_IDENTITY_POOL_ID = os.getenv('COGNITO_IDENTITY_POOL_ID')
COGNITO_CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')
APP_NAME = os.getenv('APP_NAME')

client_idp = boto3.client('cognito-idp')
client_identity = boto3.client('cognito-identity')


def user_code_input() -> str:
    user_code_regex_patter = re.compile(r'\d{6}')
    while True:
        user_code = input('Enter a code from your authenticator app: ')
        mo = user_code_regex_patter.fullmatch(user_code)
        if mo:
            return user_code
        logging.warning('Not valid user code format. Should contain 6 digits')


def authenticate_user(username: str, password: str, client_id: str) -> dict:
    try:
        response = client_idp.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            },
            ClientId=client_id
        )
    except ClientError as error:
        logger.error(error.response['Error']['Message'])
        sys.exit(1)
    return response


def main() -> None:
    # TODO: prompt function
    cognito_username: str = input('Username: ')
    cognito_password: str = pwinput(prompt='Password: ')

    auth_response = authenticate_user(
        username=cognito_username,
        password=cognito_password,
        client_id=COGNITO_CLIENT_ID
    )

    while 'ChallengeName' in auth_response:
        # TODO: while loop for challenge
        challenge_name: str = auth_response['ChallengeName']
        auth_session: str = auth_response['Session']
        print(challenge_name)

        if challenge_name == 'NEW_PASSWORD_REQUIRED':
            new_password: str = pwinput(prompt='New password: ')
            challenge_responses = {
                'USERNAME': cognito_username,
                'NEW_PASSWORD': new_password
            }
        elif challenge_name == 'MFA_SETUP':
            response = client_idp.associate_software_token(
                Session=auth_session
            )
            mfa_secret_code: str = response['SecretCode']
            otpauth_uri = f'otpauth://totp/{APP_NAME}:{cognito_username}?secret={mfa_secret_code}'

            print('Scan this QR code with your authenticator app')
            qrcode = segno.make(otpauth_uri)
            qrcode.terminal(compact=True)
            print(f'Alternatively, you can manually enter secret key in your authenticator app - {mfa_secret_code}')

            # TODO: add regex validation - [0-9]+
            mfa_user_code: str = user_code_input()
            mfa_friendly_device_name = 'MFA-test'

            try:
                response = client_idp.verify_software_token(
                    Session=response['Session'],
                    UserCode=mfa_user_code,
                    FriendlyDeviceName=mfa_friendly_device_name
                )
            except ClientError as error:
                logger.error(error.response['Error']['Message'])
                sys.exit(1)
            auth_session = response['Session']
            challenge_responses = {
                'USERNAME': cognito_username,
                'SESSION': auth_session
            }
        elif challenge_name == 'SOFTWARE_TOKEN_MFA':
            mfa_user_code: str = user_code_input()
            challenge_responses = {
                'USERNAME': cognito_username,
                'SOFTWARE_TOKEN_MFA_CODE': mfa_user_code
            }
        else:
            logger.error(f'Challenge "{challenge_name}" type is not supported')
            sys.exit(1)
        try:
            auth_response = client_idp.respond_to_auth_challenge(
                ClientId=COGNITO_CLIENT_ID,
                ChallengeName=challenge_name,
                Session=auth_session,
                ChallengeResponses=challenge_responses
            )
        except ClientError as error:
            logger.error(error.response['Error']['Message'])
            sys.exit(1)

    cognito_id_token = auth_response['AuthenticationResult']['IdToken']
    try:
        id_response = client_identity.get_id(
            IdentityPoolId=COGNITO_IDENTITY_POOL_ID,
            Logins={
                f'{COGNITO_URL}/{COGNITO_USER_POOL_ID}': cognito_id_token
            }
        )
    except ClientError as error:
        logger.error(error.response['Error']['Message'])
        sys.exit(1)
    identity_id: str = id_response['IdentityId']

    try:
        credentials = client_identity.get_credentials_for_identity(
            IdentityId=identity_id,
            Logins={
                f'{COGNITO_URL}/{COGNITO_USER_POOL_ID}': cognito_id_token
            }
        )['Credentials']
    except ClientError as error:
        logger.error(error.response['Error']['Message'])
        sys.exit(1)

    exports = {
        'AWS_ACCESS_KEY_ID': credentials['AccessKeyId'],
        'AWS_SECRET_ACCESS_KEY': credentials['SecretKey'],
        'AWS_SESSION_TOKEN': credentials['SessionToken']
    }
    for key, value in exports.items():
        print(f'export {key}={value}')


if __name__ == '__main__':
    main()
