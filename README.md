# aws-cognito-cli-login

[![Python 3.10.12](https://img.shields.io/badge/python-3.10.12-blue.svg)](https://www.python.org/downloads/release/python-377/)
[![Boto3](https://img.shields.io/badge/Boto3-1.42.3-blue.svg)](https://boto3.amazonaws.com/v1/documentation/api/latest/index.html)
[![MIT license](https://img.shields.io/badge/License-MIT-blue.svg)](https://lbesson.mit-license.org/)

A Python CLI tool for authenticating with AWS Cognito and retrieving temporary AWS credentials through Cognito Identity Pool. This tool supports password authentication, MFA setup, and TOTP-based multi-factor authentication.

## Features

- User authentication with AWS Cognito User Pool
- Support for password change on first login
- TOTP software token MFA setup with QR code generation
- Multi-factor authentication support
- Retrieve temporary AWS credentials via Cognito Identity Pool
- Multiple output formats (shell export, JSON)
- Command-line arguments for automation

## Prerequisites

- Python 3.10+
- AWS Account with Cognito User Pool and Identity Pool configured
- AWS IAM role for authenticated Cognito users

## Installation

1. Clone the repository:
```bash
git clone https://github.com/yourusername/aws-cognito-cli-login.git
cd aws-cognito-cli-login
```

2. Install dependencies:
```bash
pip install -r requirements.txt
```

3. Create `.env` file with your Cognito configuration:
```bash
COGNITO_URL=cognito-idp.us-east-1.amazonaws.com
COGNITO_USER_POOL_ID=us-east-1_XXXXXXXXX
COGNITO_IDENTITY_POOL_ID=us-east-1:xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx
COGNITO_CLIENT_ID=xxxxxxxxxxxxxxxxxxxxxxxxxx
APP_NAME=MyApp
```

## Usage

Basic usage:
```bash
python main.py
```

With command-line options:
```bash
# Specify username
python main.py -u myusername

# JSON output format
python main.py -f json

# Verbose logging
python main.py -v
```

Export credentials to environment:
```bash
eval $(python main.py)
```

## Deployment

AWS Cognito resources can be deployed using Terraform code in the `terraform/` directory:

```bash
cd terraform
terraform init
terraform plan
terraform apply
```

To customize the deployment:

```bash
terraform apply -var="name=my-cognito-app" -var="region=us-east-1" -var="environment=prod"
```

After deployment, get the outputs to configure your `.env` file:

```bash
terraform output
```

Terraform outputs:
- `user_pool_endpoint` → `COGNITO_URL`
- `user_pool_id` → `COGNITO_USER_POOL_ID`
- `identity_pool_id` → `COGNITO_IDENTITY_POOL_ID`
- `user_pool_client_id` → `COGNITO_CLIENT_ID`

## How It Works

1. User authenticates with AWS Cognito User Pool using username/password
2. Handles authentication challenges (new password, MFA setup, MFA verification)
3. Receives ID token from successful authentication
4. Exchanges ID token for AWS credentials via AWS Cognito Identity Pool
5. Outputs temporary AWS credentials (Access Key, Secret Key, Session Token)

## References
- Boto3 Amazon Cognito Federated Identities - `CognitoIdentity.Client` [documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-identity.html#cognitoidentity)
- Boto3 Amazon Cognito user pools API `CognitoIdentityProvider.Client` [documentation](https://boto3.amazonaws.com/v1/documentation/api/latest/reference/services/cognito-idp.html#cognitoidentityprovider)
- AWS Cognito - TOTP software token MFA [documentation](https://docs.aws.amazon.com/cognito/latest/developerguide/user-pool-settings-mfa-totp.html)
