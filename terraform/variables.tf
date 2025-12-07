variable "region" {
  description = "AWS region in which resources will be deployed"
  type        = string
  default     = "eu-west-1"
}

variable "name" {
  description = "Name prefix for Cognito resources"
  type        = string
  default     = "aws-cognito-cli-login"
}

variable "environment" {
  description = "Environment name (e.g., dev, staging, prod)"
  type        = string
  default     = "dev"
}

variable "additional_tags" {
  description = "Additional tags to set for all resources"
  type        = map(string)
  default     = {}
}

variable "user_pool_domain" {
  description = "Domain prefix for Cognito User Pool (leave empty to use random string)"
  type        = string
  default     = ""

  validation {
    condition     = var.user_pool_domain == "" || !can(regex("(aws|cognito)", lower(var.user_pool_domain)))
    error_message = "Domain cannot contain reserved words: aws, cognito."
  }
}

variable "authenticated_role_policy_arns" {
  description = "List of IAM policy ARNs to attach to the authenticated role"
  type        = list(string)
  default     = []
}
