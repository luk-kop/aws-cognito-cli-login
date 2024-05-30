variable "region" {
  description = "AWS region in which resources will be deployed"
  type        = string
  default     = "eu-west-1"
}

variable "additional_tags" {
  description = "Additional tags to set for all resources"
  type        = map(string)
  default     = {}
}
