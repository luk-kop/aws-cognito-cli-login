# Cognito User Pool
resource "aws_cognito_user_pool" "this" {
  name = "${var.name}-pool"

  mfa_configuration = "ON"

  admin_create_user_config {
    allow_admin_create_user_only = true
  }

  software_token_mfa_configuration {
    enabled = true
  }

  password_policy {
    minimum_length    = 8
    require_lowercase = true
    require_numbers   = true
    require_symbols   = true
    require_uppercase = true
  }

  account_recovery_setting {
    recovery_mechanism {
      name     = "verified_email"
      priority = 1
    }
  }

  auto_verified_attributes = ["email"]

  schema {
    name                = "email"
    attribute_data_type = "String"
    required            = true
    mutable             = false
  }
}

# Cognito User Pool Client
resource "aws_cognito_user_pool_client" "this" {
  name         = "${var.name}-client"
  user_pool_id = aws_cognito_user_pool.this.id

  explicit_auth_flows = [
    "ALLOW_USER_PASSWORD_AUTH",
    "ALLOW_REFRESH_TOKEN_AUTH",
    "ALLOW_USER_SRP_AUTH"
  ]

  generate_secret = false
}

# Cognito User Pool Domain
resource "aws_cognito_user_pool_domain" "this" {
  domain       = var.user_pool_domain != "" ? var.user_pool_domain : random_string.domain_suffix.result
  user_pool_id = aws_cognito_user_pool.this.id
}

# Random suffix for domain
resource "random_string" "domain_suffix" {
  length  = 8
  special = false
  upper   = false
}

# Cognito Identity Pool
resource "aws_cognito_identity_pool" "this" {
  identity_pool_name               = "${replace(var.name, "-", "_")}_identity_pool"
  allow_unauthenticated_identities = false

  cognito_identity_providers {
    client_id               = aws_cognito_user_pool_client.this.id
    provider_name           = aws_cognito_user_pool.this.endpoint
    server_side_token_check = true
  }
}

# IAM Role for Authenticated Users
resource "aws_iam_role" "authenticated" {
  name = "${var.name}-authenticated-role"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Principal = {
          Federated = "cognito-identity.amazonaws.com"
        }
        Action = "sts:AssumeRoleWithWebIdentity"
        Condition = {
          StringEquals = {
            "cognito-identity.amazonaws.com:aud" = aws_cognito_identity_pool.this.id
          }
          "ForAnyValue:StringLike" = {
            "cognito-identity.amazonaws.com:amr" = "authenticated"
          }
        }
      }
    ]
  })
}

# IAM Policy for Authenticated Users
resource "aws_iam_role_policy" "authenticated" {
  name = "${var.name}-authenticated-policy"
  role = aws_iam_role.authenticated.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "cognito-identity:GetCredentialsForIdentity",
          "cognito-identity:GetId"
        ]
        Resource = "*"
      }
    ]
  })
}

# Attach Identity Pool Roles
resource "aws_cognito_identity_pool_roles_attachment" "this" {
  identity_pool_id = aws_cognito_identity_pool.this.id

  roles = {
    authenticated = aws_iam_role.authenticated.arn
  }
}
