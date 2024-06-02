import os
import sys
import logging

import boto3
from botocore.exceptions import ClientError
from pwinput import pwinput
from dotenv import load_dotenv
import segno

logging.basicConfig(level=logging.INFO, format='%(levelname)s - %(message)s')
logger = logging.getLogger()
logging.getLogger('botocore').setLevel(logging.WARNING)

client_idp = boto3.client('cognito-idp')
client_identity = boto3.client('cognito-identity')


def main() -> None:
    pass


if __name__ == '__main__':
    load_dotenv('.env')

    # TODO: env validation
    COGNITO_URL = os.getenv('COGNITO_URL')
    COGNITO_USER_POOL_ID = os.getenv('COGNITO_USER_POOL_ID')
    COGNITO_IDENTITY_POOL_ID = os.getenv('COGNITO_IDENTITY_POOL_ID')
    COGNITO_CLIENT_ID = os.getenv('COGNITO_CLIENT_ID')

    # TODO: prompt function
    username: str = input('Username: ')
    password: str = pwinput(prompt='Password: ')
    try:
        auth_response = client_idp.initiate_auth(
            AuthFlow='USER_PASSWORD_AUTH',
            AuthParameters={
                'USERNAME': username,
                'PASSWORD': password
            },
            ClientId=COGNITO_CLIENT_ID
        )
    except ClientError as error:
        logger.error(error.response['Error']['Message'])
        sys.exit(1)

    if 'ChallengeName' in auth_response:
        # TODO: while loop for challenge
        challenge_name: str = auth_response['ChallengeName']
        print(challenge_name)
        if challenge_name == 'NEW_PASSWORD_REQUIRED':
            new_password: str = pwinput(prompt='New password: ')
            challenge_responses = {
                'USERNAME': username,
                'NEW_PASSWORD': new_password
            }
        elif challenge_name == 'MFA_SETUP':
            session = auth_response['Session']
            response = client_idp.associate_software_token(
                # AccessToken=cognito_access_token,
                Session=session
            )

            mfa_secret_code: str = response['SecretCode']
            otpauth = f'otpauth://totp/cognito-test:{username}?secret={mfa_secret_code}&issuer={COGNITO_URL}'
            mfa_session: str = response['Session']

            print('Scan this QR code with your authenticator app')
            qrcode = segno.make(otpauth)
            qrcode.terminal(compact=True)
            print(f'Alternatively, you can manually enter secret key in your authenticator app - {mfa_secret_code}')

            # TODO: add regex validation - [0-9]+
            user_code = input('Enter a code from your authenticator app: ')
            mfa_friendly_device_name = 'MFA-test'

            try:
                response = client_idp.verify_software_token(
                    Session=mfa_session,
                    UserCode=user_code,
                    FriendlyDeviceName=mfa_friendly_device_name
                )
            except ClientError as error:
                logger.error(error.response['Error']['Message'])
                sys.exit(1)
            session: str = response['Session']
            challenge_responses = {
                'USERNAME': username,
                'SESSION': session
            }
        elif challenge_name == 'SOFTWARE_TOKEN_MFA':
            user_code = input('Enter a code from your authenticator app: ')
            challenge_responses = {
                'USERNAME': username,
                'SOFTWARE_TOKEN_MFA_CODE': user_code
            }
        else:
            logger.error(f'Challenge "{challenge_name}" is not supported')
            sys.exit(1)
        try:
            auth_response = client_idp.respond_to_auth_challenge(
                ClientId=COGNITO_CLIENT_ID,
                ChallengeName=challenge_name,
                Session=auth_response['Session'],
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
