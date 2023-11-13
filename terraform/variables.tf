variable "orgname" {
  description = ""
  type        = string
  default     = "medium"
}

variable "Role" {
  description = ""
  type        = string
  default     = "vault"
}

variable "owner" {
  type        = string
  default     = "alex"
  description = ""
}

variable "environmentTier" {
  type        = string
  default     = "lower"
  description = "devops"
}

# ---------------------------------------------------------
# KMS Variables
# ---------------------------------------------------------

variable "kms_deletion_window_in_days" {
  type        = number
  default     = 10
  description = "Duration in days after which the key is deleted after destruction of the resource"
}

variable "kms_enable_key_rotation" {
  type        = bool
  default     = true
  description = "Specifies whether key rotation is enabled"
}

variable "kms_description" {
  type        = string
  default     = "Parameter Store KMS master key"
  description = "The description of the key as viewed in AWS console"
}

variable "kms_policy" {
  type        = string
  default     = ""
  description = "A valid KMS policy JSON document. Note that if the policy document is not specific enough (but still valid), Terraform may view the policy as constantly changing in a terraform plan. In this case, please make sure you use the verbose/specific version of the policy."
}

# ---------------------------------------------------------
# S3 Variables
# ---------------------------------------------------------

variable "s3_acl" {
  type        = string
  default     = "private"
  description = "The canned ACL to apply. We recommend `private` to avoid exposing sensitive information. Conflicts with grant"
}

variable "s3_force_destroy" {
  type        = bool
  default     = false
  description = "A boolean string that indicates all objects should be deleted from the bucket so that the bucket can be destroyed without error. These objects are not recoverable"
}

variable "s3_sse_algorithm" {
  type        = string
  default     = "AES256"
  description = "The server-side encryption algorithm to use. Valid values are `AES256` and `aws:kms`"
}

variable "s3_kms_master_key_arn" {
  type        = string
  default     = ""
  description = "The AWS KMS master key ARN used for the `SSE-KMS` encryption. This can only be used when you set the value of `sse_algorithm` as `aws:kms`. The default aws/s3 AWS KMS master key is used if this element is absent while the `sse_algorithm` is `aws:kms`"
}

variable "s3_block_public_acls" {
  type        = bool
  default     = true
  description = "Set to `false` to disable the blocking of new public access lists on the bucket"
}

variable "s3_block_public_policy" {
  type        = bool
  default     = true
  description = "Set to `false` to disable the blocking of new public policies on the bucket"
}

variable "s3_ignore_public_acls" {
  type        = bool
  default     = true
  description = "Set to `false` to disable the ignoring of public access lists on the bucket"
}

variable "s3_restrict_public_buckets" {
  type        = bool
  default     = true
  description = "Set to `false` to disable the restricting of making the bucket public"
}

variable "s3_versioning_enabled" {
  type        = bool
  default     = false
  description = "Enable bucket versioning"
}