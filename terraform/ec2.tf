data "aws_ami" "ubuntu" {
  most_recent = true

  filter {
    name   = "name"
    values = ["ubuntu/images/hvm-ssd/ubuntu-focal-20.04-amd64-server-*"]
  }

  filter {
    name   = "virtualization-type"
    values = ["hvm"]
  }

  owners = ["099720109477"] # Canonical
}

resource "tls_private_key" "vault_ec2" {
  algorithm = "RSA"
  rsa_bits  = 4096
}

resource "aws_key_pair" "vault_ec2" {
  key_name   = "vault-ssh-key"
  public_key = tls_private_key.vault_ec2.public_key_openssh
}


resource "aws_instance" "vault_ec2" {
  ami                  = data.aws_ami.ubuntu.id
  instance_type        = "t2.nano"
  tags                 = local.tags
  iam_instance_profile = aws_iam_instance_profile.vault_iam.id
  key_name             = aws_key_pair.vault_ec2.key_name
}
