resource "aws_kms_key" "vault_kms" {
  deletion_window_in_days = var.kms_deletion_window_in_days
  enable_key_rotation     = var.kms_enable_key_rotation
  policy                  = var.kms_policy
  tags                    = local.tags
  description             = var.kms_description
}

resource "aws_kms_alias" "vault_kms" {
  name          = "alias/${var.Role}-kms"
  target_key_id = aws_kms_key.vault_kms.id
}
