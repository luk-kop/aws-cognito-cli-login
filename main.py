import argparse
import json
import logging
import os
import re
import sys
from dataclasses import dataclass
from typing import Any

import boto3
from botocore.exceptions import ClientError
from pwinput import pwinput
from dotenv import load_dotenv
import segno


logging.basicConfig(level=logging.INFO, format="%(levelname)s - %(message)s")
logger = logging.getLogger()
logging.getLogger("botocore").setLevel(logging.WARNING)

# Challenge types
CHALLENGE_NEW_PASSWORD = "NEW_PASSWORD_REQUIRED"
CHALLENGE_MFA_SETUP = "MFA_SETUP"
CHALLENGE_SOFTWARE_TOKEN_MFA = "SOFTWARE_TOKEN_MFA"


@dataclass
class Config:
    """Application configuration loaded from environment variables."""

    cognito_url: str
    user_pool_id: str
    identity_pool_id: str
    client_id: str
    app_name: str

    @classmethod
    def from_env(cls) -> "Config":
        """Load configuration from environment variables."""
        load_dotenv(".env")

        config = cls(
            cognito_url=os.getenv("COGNITO_URL", ""),
            user_pool_id=os.getenv("COGNITO_USER_POOL_ID", ""),
            identity_pool_id=os.getenv("COGNITO_IDENTITY_POOL_ID", ""),
            client_id=os.getenv("COGNITO_CLIENT_ID", ""),
            app_name=os.getenv("APP_NAME", ""),
        )
        config.validate()
        return config

    def validate(self) -> None:
        """Validate that all required configuration values are present."""
        missing = [
            field
            for field in [
                "cognito_url",
                "user_pool_id",
                "identity_pool_id",
                "client_id",
                "app_name",
            ]
            if not getattr(self, field)
        ]
        if missing:
            env_names = {
                "cognito_url": "COGNITO_URL",
                "user_pool_id": "COGNITO_USER_POOL_ID",
                "identity_pool_id": "COGNITO_IDENTITY_POOL_ID",
                "client_id": "COGNITO_CLIENT_ID",
                "app_name": "APP_NAME",
            }
            missing_env = [env_names[f] for f in missing]
            logger.error(
                f"Missing required environment variables: {', '.join(missing_env)}"
            )
            sys.exit(1)


class CognitoClient:
    """Wrapper for Cognito boto3 clients."""

    def __init__(self, config: Config):
        self.config = config
        self.idp = boto3.client("cognito-idp")
        self.identity = boto3.client("cognito-identity")
        self.provider_name = f"{config.cognito_url}/{config.user_pool_id}"


def get_mfa_code() -> str:
    """Prompt user for MFA code with validation."""
    user_code_regex_pattern = re.compile(r"\d{6}")
    while True:
        user_code = input("Enter a code from your authenticator app: ")
        if user_code_regex_pattern.fullmatch(user_code):
            return user_code
        logger.warning("Invalid code format. Must be 6 digits")


def handle_new_password_challenge(username: str) -> dict[str, str]:
    """Handle new password required challenge."""
    new_password = pwinput(prompt="New password: ")
    return {"USERNAME": username, "NEW_PASSWORD": new_password}


def handle_mfa_setup(
    client: CognitoClient, username: str, session: str
) -> tuple[dict[str, str], str]:
    """Handle MFA setup challenge."""
    try:
        response = client.idp.associate_software_token(Session=session)
    except ClientError as error:
        logger.error(error.response["Error"]["Message"])
        sys.exit(1)

    mfa_secret_code = response["SecretCode"]
    otpauth_uri = (
        f"otpauth://totp/{client.config.app_name}:{username}?secret={mfa_secret_code}"
    )

    print("Scan this QR code with your authenticator app")
    qrcode = segno.make(otpauth_uri)
    qrcode.terminal(compact=True)
    print(f"Or manually enter this secret key: {mfa_secret_code}")

    mfa_user_code = get_mfa_code()

    try:
        verify_response = client.idp.verify_software_token(
            Session=response["Session"],
            UserCode=mfa_user_code,
            FriendlyDeviceName="CLI-MFA-Device",
        )
    except ClientError as error:
        logger.error(error.response["Error"]["Message"])
        sys.exit(1)

    return {
        "USERNAME": username,
        "SESSION": verify_response["Session"],
    }, verify_response["Session"]


def handle_software_token_mfa(username: str) -> dict[str, str]:
    """Handle software token MFA challenge."""
    mfa_user_code = get_mfa_code()
    return {"USERNAME": username, "SOFTWARE_TOKEN_MFA_CODE": mfa_user_code}


def authenticate_user(
    client: CognitoClient, username: str, password: str
) -> dict[str, Any]:
    """Initiate user authentication."""
    try:
        response = client.idp.initiate_auth(
            AuthFlow="USER_PASSWORD_AUTH",
            AuthParameters={"USERNAME": username, "PASSWORD": password},
            ClientId=client.config.client_id,
        )
    except ClientError as error:
        logger.error(error.response["Error"]["Message"])
        sys.exit(1)
    return response


def handle_auth_challenges(
    client: CognitoClient, username: str, auth_response: dict[str, Any]
) -> dict[str, Any]:
    """Handle authentication challenges."""
    while "ChallengeName" in auth_response:
        challenge_name = auth_response["ChallengeName"]
        auth_session = auth_response["Session"]
        logger.info(f"Challenge: {challenge_name}")

        if challenge_name == CHALLENGE_NEW_PASSWORD:
            challenge_responses = handle_new_password_challenge(username)
        elif challenge_name == CHALLENGE_MFA_SETUP:
            challenge_responses, auth_session = handle_mfa_setup(
                client, username, auth_session
            )
        elif challenge_name == CHALLENGE_SOFTWARE_TOKEN_MFA:
            challenge_responses = handle_software_token_mfa(username)
        else:
            logger.error(f"Unsupported challenge type: {challenge_name}")
            sys.exit(1)

        try:
            auth_response = client.idp.respond_to_auth_challenge(
                ClientId=client.config.client_id,
                ChallengeName=challenge_name,
                Session=auth_session,
                ChallengeResponses=challenge_responses,
            )
        except ClientError as error:
            logger.error(error.response["Error"]["Message"])
            sys.exit(1)

    return auth_response


def get_aws_credentials(client: CognitoClient, id_token: str) -> dict[str, Any]:
    """Retrieve AWS credentials from Cognito Identity Pool."""
    try:
        id_response = client.identity.get_id(
            IdentityPoolId=client.config.identity_pool_id,
            Logins={client.provider_name: id_token},
        )
        identity_id = id_response["IdentityId"]

        credentials = client.identity.get_credentials_for_identity(
            IdentityId=identity_id, Logins={client.provider_name: id_token}
        )["Credentials"]
    except ClientError as error:
        logger.error(error.response["Error"]["Message"])
        sys.exit(1)

    return credentials


def change_password(client: CognitoClient, access_token: str) -> None:
    """Change user password."""
    old_password = pwinput(prompt="Current password: ")
    new_password = pwinput(prompt="New password: ")
    confirm_password = pwinput(prompt="Confirm new password: ")

    if new_password != confirm_password:
        logger.error("Passwords do not match")
        sys.exit(1)

    try:
        client.idp.change_password(
            PreviousPassword=old_password,
            ProposedPassword=new_password,
            AccessToken=access_token,
        )
        logger.info("Password changed successfully")
    except ClientError as error:
        logger.error(error.response["Error"]["Message"])
        sys.exit(1)


def output_credentials(credentials: dict[str, Any], output_format: str) -> None:
    """Output credentials in specified format."""
    expiration = credentials["Expiration"]
    logger.info(f"Credentials expire at: {expiration.strftime('%Y-%m-%d %H:%M:%S %Z')}")

    if output_format == "export":
        print(f"export AWS_ACCESS_KEY_ID={credentials['AccessKeyId']}")
        print(f"export AWS_SECRET_ACCESS_KEY={credentials['SecretKey']}")
        print(f"export AWS_SESSION_TOKEN={credentials['SessionToken']}")
    elif output_format == "json":
        output = {
            "AccessKeyId": credentials["AccessKeyId"],
            "SecretAccessKey": credentials["SecretKey"],
            "SessionToken": credentials["SessionToken"],
            "Expiration": expiration.isoformat(),
        }
        print(json.dumps(output, indent=2))


def main() -> None:
    """Main entry point."""
    parser = argparse.ArgumentParser(description="AWS Cognito CLI Login")
    parser.add_argument("-u", "--username", help="Cognito username")
    parser.add_argument("-p", "--password", help="Cognito password")
    parser.add_argument(
        "-f",
        "--format",
        choices=["export", "json"],
        default="export",
        help="Output format (default: export)",
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument(
        "--change-password", action="store_true", help="Change password"
    )
    args = parser.parse_args()

    if args.verbose:
        logger.setLevel(logging.DEBUG)

    config = Config.from_env()
    client = CognitoClient(config)

    username = args.username or input("Username: ")
    password = args.password or pwinput(prompt="Password: ")

    auth_response = authenticate_user(client, username, password)
    auth_response = handle_auth_challenges(client, username, auth_response)

    if args.change_password:
        access_token = auth_response["AuthenticationResult"]["AccessToken"]
        change_password(client, access_token)
        return

    id_token = auth_response["AuthenticationResult"]["IdToken"]
    credentials = get_aws_credentials(client, id_token)

    output_credentials(credentials, args.format)


if __name__ == "__main__":
    main()
