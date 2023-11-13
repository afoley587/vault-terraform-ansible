output "private_key" {
  value     = tls_private_key.vault_ec2.private_key_pem
  sensitive = true
}

output "iam_access_key" {
  value     = aws_iam_access_key.vault_iam.id
  sensitive = true
}

output "iam_secret_key" {
  value     = aws_iam_access_key.vault_iam.secret
  sensitive = true
}

output "s3_bucket_name" {
  value     = aws_s3_bucket.vault_s3.id
  sensitive = false
}

output "kms_key_alias" {
  value     = aws_kms_alias.vault_kms.name
  sensitive = false
}

# terraform output -raw private_key > /tmp/vault-ssh
# chmod 600 /tmp/vault-ssh
# iam_access_key=$(terraform output -raw iam_access_key)
# iam_secret_key=$(terraform output -raw iam_secret_key)
# s3_bucket_name=$(terraform output -raw s3_bucket_name)
# kms_key_alias=$(terraform output -raw kms_key_alias)
# poetry run ansible-playbook -i inventory site.yml -e iam_access_key=$iam_access_key \
#   -e iam_secret_key=$iam_secret_key \
#   -e s3_bucket_name=$s3_bucket_name \
#   -e kms_key_alias=$kms_key_alias 