resource "random_id" "suffix" {
  byte_length = 4
}

resource "aws_s3_bucket" "vault_s3" {
  bucket        = "vaults3medium${random_id.suffix.hex}"
  force_destroy = var.s3_force_destroy
  tags          = local.tags
}

resource "aws_s3_bucket_public_access_block" "vault_s3" {
  bucket                  = aws_s3_bucket.vault_s3.id
  block_public_acls       = var.s3_block_public_acls
  block_public_policy     = var.s3_block_public_policy
  ignore_public_acls      = var.s3_ignore_public_acls
  restrict_public_buckets = var.s3_restrict_public_buckets
}

resource "aws_s3_bucket_versioning" "vault_s3" {
  count  = var.s3_versioning_enabled ? 1 : 0
  bucket = aws_s3_bucket.vault_s3.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "vault_s3" {
  bucket = aws_s3_bucket.vault_s3.id

  rule {
    apply_server_side_encryption_by_default {
      kms_master_key_id = var.s3_kms_master_key_arn
      sse_algorithm     = var.s3_sse_algorithm
    }
  }
}