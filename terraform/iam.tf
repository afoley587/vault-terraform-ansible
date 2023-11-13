# Vault For EC2
resource "aws_iam_instance_profile" "vault_iam" {
  name = "vaultIam"
  role = aws_iam_role.vault_iam.name
}

resource "aws_iam_role" "vault_iam" {
  name               = "vaultIam"
  assume_role_policy = data.aws_iam_policy_document.vault_iam.json
}

data "aws_iam_policy_document" "vault_iam" {
  statement {
    effect = "Allow"

    principals {
      type = "Service"

      identifiers = [
        "ec2.amazonaws.com",
        "ssm.amazonaws.com",
      ]
    }

    actions = ["sts:AssumeRole"]
  }
}

resource "aws_iam_role_policy_attachment" "vault_iam" {
  role       = aws_iam_role.vault_iam.name
  policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
}

# Vault User
resource "aws_iam_user" "vault_iam" {
  name = "vaultUser"
}

resource "aws_iam_access_key" "vault_iam" {
  user = aws_iam_user.vault_iam.name
}

resource "aws_iam_policy" "vault_iam" {
  name        = "vaultUser"
  description = "Used by Vault perform cloud unseal and access S3."
  policy      = <<-EOF
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": ["s3:*"],
      "Resource": ["${aws_s3_bucket.vault_s3.arn}"]
    },
    {
      "Effect": "Allow",
      "Action": ["s3:*"],
      "Resource": ["${aws_s3_bucket.vault_s3.arn}/*"]
    },
    {
      "Effect": "Allow",
      "Action": ["kms:*"],
      "Resource": ["${aws_kms_key.vault_kms.arn}"]
    }
  ]
}
EOF
}

resource "aws_iam_user_policy_attachment" "vault_iam" {
  user       = aws_iam_user.vault_iam.name
  policy_arn = aws_iam_policy.vault_iam.arn
}

