output "user_pool_id" {
  description = "Cognito User Pool ID"
  value       = aws_cognito_user_pool.this.id
}

output "user_pool_endpoint" {
  description = "Cognito User Pool endpoint URL"
  value       = aws_cognito_user_pool.this.endpoint
}

output "user_pool_client_id" {
  description = "Cognito User Pool Client ID"
  value       = aws_cognito_user_pool_client.this.id
}

output "identity_pool_id" {
  description = "Cognito Identity Pool ID"
  value       = aws_cognito_identity_pool.this.id
}

output "authenticated_role_arn" {
  description = "IAM Role ARN for authenticated users"
  value       = aws_iam_role.authenticated.arn
}

output "region" {
  description = "AWS Region"
  value       = var.region
}

output "hosted_ui_url" {
  description = "Cognito Hosted UI URL"
  value       = "https://${aws_cognito_user_pool_domain.this.domain}.auth.${var.region}.amazoncognito.com"
}
