locals {
  tags = merge(
    var.additional_tags,
    {
      Project     = "aws-cognito-cli-login",
      Environment = var.environment,
      Terraform   = "true"
    }
  )
}
