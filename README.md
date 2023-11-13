# One Dollar Devops: Deploying HashiVault With Terraform + Ansible

In the ever-evolving landscape of cloud computing, securing sensitive 
information and managing access credentials are paramount challenges 
for organizations. HashiCorp Vault emerges as a robust solution, 
providing a comprehensive platform for managing secrets, encryption 
keys, and other sensitive data across dynamic infrastructure. In this 
blog post, we will delve into the intricate world of deploying HashiCorp 
Vault on the AWS cloud using two powerful automation tools: Terraform and Ansible.

![Thumbnail](./images/thumbnail.png)

1. What is HashiCorp Vault?
HashiCorp Vault is a dynamic and flexible open-source tool designed to secure, 
store, and control access to sensitive information within a modern infrastructure. 
As organizations transition to cloud-native architectures, the need for a 
centralized and secure repository for managing secrets becomes imperative. 
Vault not only safeguards credentials but also offers features such as encryption 
as a service, dynamic secrets, and robust access controls. Its versatility makes 
it an ideal choice for enterprises seeking a unified solution to their security 
challenges in the cloud era.

2. What is Terraform?
Terraform, developed by HashiCorp, is an infrastructure as code (IaC) 
tool that enables users to define and provision infrastructure in a declarative 
configuration language. With Terraform, users can codify their infrastructure 
requirements and deploy resources seamlessly across various cloud providers, 
including AWS. Its primary strength lies in its ability to maintain and version 
infrastructure code, ensuring consistency and reproducibility. In this blog post, 
we'll harness Terraform's capabilities to orchestrate the foundational AWS 
infrastructure required for HashiCorp Vault deployment.

3. What is Ansible?
Ansible, another powerful open-source tool, specializes in configuration 
management, application deployment, and task automation. Unlike Terraform, 
Ansible employs an agentless architecture, making it lightweight and easy to integrate 
into existing environments. With Ansible, users can automate complex workflows, 
ensuring efficiency and consistency in managing infrastructure. In this blog post, 
we'll leverage Ansible's automation prowess to configure and fine-tune the 
HashiCorp Vault deployment on AWS, completing the end-to-end automation cycle.

In the end, we look to combine terraform and ansible to give you a seamless, button-push
way to deploy a new Vault instance for you on EC2. To follow best practices, we will
also utilize AWS KMS to encrypt our vault secrets and leverage an S3 backend to make 
our instance as stateless as possible.

## Assumptions and Requirements

I will assume you have the following software installed on your computer:
1. [Terraform](https://developer.hashicorp.com/terraform/install)
2. [Python](https://www.python.org/downloads/)
3. [AWS CLI](https://docs.aws.amazon.com/cli/latest/userguide/getting-started-install.html)
4. [Python Requirements]()

I will also assume you have an AWS account setup.

## Terraform: Setting Up AWS Services
Let's discuss our immutable infrastructure first. Our system is going to be comprised of
one AWS EC2 instance, an AWS S3 bucket, and AWS KMS for encryption keys. To secure things a 
bit further, we will also be using SSM instead of SSH for access to the instance. The 
EC2 instance will run Vault as a systemd service. It will leverage the S3 bucket
as its storage backend, and it will use the KMS key for encryption and decryption
while putting and retrieving objects from the bucket.

An amazing expansion of this project would be to add a Route53 DNS record and an application load balancer in front of the instance.

Let's go through our terraform to see how to provision each piece
of infrastructure. 

### IAM + EC2
Let's start with our IAM access and EC2 instance:

```hcl
###################
# iam.tf
###################

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

###################
# ec2.tf
###################
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
```

Within our `iam.tf` file, we have two main goals:

1. Create an instance template for our EC2 instance
2. Create an IAM user for vault

Alternatively, you could have removed #2 and updated the 
instance profile to include the S3 and KMS access.

Let's start with our instance template. First, we declare a new
resource of `aws_iam_role.vault_iam` which is able to assume the role
declared by `aws_iam_policy_document.vault_iam`. `aws_iam_policy_document.vault_iam`
is a service role for EC2 and SSM. We also want to attach the following
policy to the `arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore` policy
to the instance template so that we are able to use the `aws ssm start-session`
commands instead of just SSH-ing in to our instance with private keys. Doing
so allows us to keep our security groups locked down because SSM can proxy the
SSH traffic.

We also wanted to create a new user which the vault binary will use to 
interact with both S3 and KMS. We can do this by declaring a new
`aws_iam_user.vault_iam` resource and attaching the `aws_iam_policy.vault_iam`
resource to it. `aws_iam_policy.vault_iam` allows the users full access on 
the vault bucket we will make next as well as the kms key which we will make
shortly.

We can now provision our EC2 instance. We start by gathering the most
recent Ubuntu 20.04 AMI from AWS with `data.aws_ami.ubuntu`. We also
generate a TLS keypair with `tls_private_key.vault_ec2`. Note that doing
this in terraform will have some security concerns because your TLS
private keys are now stored in your terraform state. It might be more beneficial
to pass the public key in as a variable in your production environment.

Finally, we can make an AWS key pair with `aws_key_pair.vault_ec2` using our
TLS key from above and then provision our instance. You might be wondering:

"Why do I need SSH keys if we are using SSM?"

And that's a good question. We will be using both SSH and SSM technically.
We will be using SSM to proxy our SSH traffic - meaning that we will need
the SSH keys for linux authentication, but will be using SSM for AWS 
authentication (instead of relying on IP whitelisting).

We now have an EC2 instance and all relevant IAM access set up. Let's switch
gears and provision our S3 bucket and resources:

### S3
```hcl
###################
# s3.tf
###################
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
```

We first want to generate a unique suffix for our bucket. If you're
not aware, S3 bucket names are global across all accounts, so having
a random suffix at the end usually helps me when I'm spinning them
up and tearing them down repeatedly!

We next declare our bucket with the `aws_s3_bucket.vault_s3` resource.
This resource will go and build our S3 bucket and give it the name
`vaults3medium<ouruniquesuffix>`. Next, we want to make sure that
we follow the S3 best practices with:

* Public Access Blocks
* Versioning
* Server Side Encryption

We can add the public access blocks with the 
`aws_s3_bucket_public_access_block.vault_s3` resource. Note that all of
the default variables for blocking public acls, blocking policies, 
restricting public buckets, etc. are `true`. Meaning that, unless specified
by the user, these will be enforced to follow S3 best practices.

We can then enable versioning with the `aws_s3_bucket_versioning.vault_s3` resource.
This is a toggleable resource. The default value for the toggle is `true` meaning
that versioning will be on by default.

Finally, we can enable the server side encryption with the 
`aws_s3_bucket_server_side_encryption_configuration.vault_s3`
resource. The default values for `s3_sse_algorithm` and `s3_kms_master_key_arn`
are `AES256` and a blank string respectively. With these settings, you will
be using the default AWS encryption mechanisms. If you wanted to encrypt these
with AWS Customer Managed Keys instead, you could use the `aws:kms` setting
instead of `AES256` and your KMS key ID instead of the blank string.

### KMS
Finally, we will want to provision our KMS keys. Note that these are going
to be used for vault client-side encryption and not S3 server-side
encryption. Our server-side encryption will be using the `AES256` mechanism
described above. When vault uploads or downloads something, it will use the
KMS key we are about to provision to encrypt or decrypt, respectively.

```hcl
###################
# kms.tf
###################
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
```

We first generate a new KMS key with the `aws_kms_key.vault_kms`
resource. Next, generate an alias for the key, which is what we will
pass to vault. An alias is just a friendly name for the key instead
of some long UUID-looking string. You could have used the key ID instead
if desired.

### Running Terraform
We now have all of our terraform code written and ready to be provisioned!

Let's kick it off with a `terraform plan` and `terraform apply`:

```shell
prompt> terraform plan -out /tmp/plan

Terraform used the selected providers to generate the following execution plan. Resource actions are indicated with the following symbols:
  + create

Terraform will perform the following actions:

  # aws_iam_access_key.vault_iam will be created
  + resource "aws_iam_access_key" "vault_iam" {
      + create_date                    = (known after apply)
      + encrypted_secret               = (known after apply)
      + encrypted_ses_smtp_password_v4 = (known after apply)
      + id                             = (known after apply)
      + key_fingerprint                = (known after apply)
      + secret                         = (sensitive value)
      + ses_smtp_password_v4           = (sensitive value)
      + status                         = "Active"
      + user                           = "vaultUser"
    }

  # aws_iam_instance_profile.vault_iam will be created
  + resource "aws_iam_instance_profile" "vault_iam" {
      + arn         = (known after apply)
      + create_date = (known after apply)
      + id          = (known after apply)
      + name        = "vaultIam"
      + name_prefix = (known after apply)
      + path        = "/"
      + role        = "vaultIam"
      + tags_all    = (known after apply)
      + unique_id   = (known after apply)
    }

  # aws_iam_policy.vault_iam will be created
  + resource "aws_iam_policy" "vault_iam" {
      + arn         = (known after apply)
      + description = "Used by Vault perform cloud unseal and access S3."
      + id          = (known after apply)
      + name        = "vaultUser"
      + name_prefix = (known after apply)
      + path        = "/"
      + policy      = (known after apply)
      + policy_id   = (known after apply)
      + tags_all    = (known after apply)
    }

  # aws_iam_role.vault_iam will be created
  + resource "aws_iam_role" "vault_iam" {
      + arn                   = (known after apply)
      + assume_role_policy    = jsonencode(
            {
              + Statement = [
                  + {
                      + Action    = "sts:AssumeRole"
                      + Effect    = "Allow"
                      + Principal = {
                          + Service = [
                              + "ssm.amazonaws.com",
                              + "ec2.amazonaws.com",
                            ]
                        }
                    },
                ]
              + Version   = "2012-10-17"
            }
        )
      + create_date           = (known after apply)
      + force_detach_policies = false
      + id                    = (known after apply)
      + managed_policy_arns   = (known after apply)
      + max_session_duration  = 3600
      + name                  = "vaultIam"
      + name_prefix           = (known after apply)
      + path                  = "/"
      + tags_all              = (known after apply)
      + unique_id             = (known after apply)

      + inline_policy {
          + name   = (known after apply)
          + policy = (known after apply)
        }
    }

  # aws_iam_role_policy_attachment.vault_iam will be created
  + resource "aws_iam_role_policy_attachment" "vault_iam" {
      + id         = (known after apply)
      + policy_arn = "arn:aws:iam::aws:policy/AmazonSSMManagedInstanceCore"
      + role       = "vaultIam"
    }

  # aws_iam_user.vault_iam will be created
  + resource "aws_iam_user" "vault_iam" {
      + arn           = (known after apply)
      + force_destroy = false
      + id            = (known after apply)
      + name          = "vaultUser"
      + path          = "/"
      + tags_all      = (known after apply)
      + unique_id     = (known after apply)
    }

  # aws_iam_user_policy_attachment.vault_iam will be created
  + resource "aws_iam_user_policy_attachment" "vault_iam" {
      + id         = (known after apply)
      + policy_arn = (known after apply)
      + user       = "vaultUser"
    }

  # aws_instance.vault_ec2 will be created
  + resource "aws_instance" "vault_ec2" {
      + ami                                  = "ami-073e5edf4b5d15fc8"
      + arn                                  = (known after apply)
      + associate_public_ip_address          = (known after apply)
      + availability_zone                    = (known after apply)
      + cpu_core_count                       = (known after apply)
      + cpu_threads_per_core                 = (known after apply)
      + disable_api_stop                     = (known after apply)
      + disable_api_termination              = (known after apply)
      + ebs_optimized                        = (known after apply)
      + get_password_data                    = false
      + host_id                              = (known after apply)
      + host_resource_group_arn              = (known after apply)
      + iam_instance_profile                 = (known after apply)
      + id                                   = (known after apply)
      + instance_initiated_shutdown_behavior = (known after apply)
      + instance_lifecycle                   = (known after apply)
      + instance_state                       = (known after apply)
      + instance_type                        = "t2.nano"
      + ipv6_address_count                   = (known after apply)
      + ipv6_addresses                       = (known after apply)
      + key_name                             = "vault-ssh-key"
      + monitoring                           = (known after apply)
      + outpost_arn                          = (known after apply)
      + password_data                        = (known after apply)
      + placement_group                      = (known after apply)
      + placement_partition_number           = (known after apply)
      + primary_network_interface_id         = (known after apply)
      + private_dns                          = (known after apply)
      + private_ip                           = (known after apply)
      + public_dns                           = (known after apply)
      + public_ip                            = (known after apply)
      + secondary_private_ips                = (known after apply)
      + security_groups                      = (known after apply)
      + source_dest_check                    = true
      + spot_instance_request_id             = (known after apply)
      + subnet_id                            = (known after apply)
      + tags                                 = {
          + "Role"    = "vault"
          + "orgname" = "medium"
          + "owner"   = "alex"
          + "tier"    = "lower"
        }
      + tags_all                             = {
          + "Role"    = "vault"
          + "orgname" = "medium"
          + "owner"   = "alex"
          + "tier"    = "lower"
        }
      + tenancy                              = (known after apply)
      + user_data                            = (known after apply)
      + user_data_base64                     = (known after apply)
      + user_data_replace_on_change          = false
      + vpc_security_group_ids               = (known after apply)

      + capacity_reservation_specification {
          + capacity_reservation_preference = (known after apply)

          + capacity_reservation_target {
              + capacity_reservation_id                 = (known after apply)
              + capacity_reservation_resource_group_arn = (known after apply)
            }
        }

      + cpu_options {
          + amd_sev_snp      = (known after apply)
          + core_count       = (known after apply)
          + threads_per_core = (known after apply)
        }

      + ebs_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + snapshot_id           = (known after apply)
          + tags                  = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }

      + enclave_options {
          + enabled = (known after apply)
        }

      + ephemeral_block_device {
          + device_name  = (known after apply)
          + no_device    = (known after apply)
          + virtual_name = (known after apply)
        }

      + instance_market_options {
          + market_type = (known after apply)

          + spot_options {
              + instance_interruption_behavior = (known after apply)
              + max_price                      = (known after apply)
              + spot_instance_type             = (known after apply)
              + valid_until                    = (known after apply)
            }
        }

      + maintenance_options {
          + auto_recovery = (known after apply)
        }

      + metadata_options {
          + http_endpoint               = (known after apply)
          + http_protocol_ipv6          = (known after apply)
          + http_put_response_hop_limit = (known after apply)
          + http_tokens                 = (known after apply)
          + instance_metadata_tags      = (known after apply)
        }

      + network_interface {
          + delete_on_termination = (known after apply)
          + device_index          = (known after apply)
          + network_card_index    = (known after apply)
          + network_interface_id  = (known after apply)
        }

      + private_dns_name_options {
          + enable_resource_name_dns_a_record    = (known after apply)
          + enable_resource_name_dns_aaaa_record = (known after apply)
          + hostname_type                        = (known after apply)
        }

      + root_block_device {
          + delete_on_termination = (known after apply)
          + device_name           = (known after apply)
          + encrypted             = (known after apply)
          + iops                  = (known after apply)
          + kms_key_id            = (known after apply)
          + tags                  = (known after apply)
          + throughput            = (known after apply)
          + volume_id             = (known after apply)
          + volume_size           = (known after apply)
          + volume_type           = (known after apply)
        }
    }

  # aws_key_pair.vault_ec2 will be created
  + resource "aws_key_pair" "vault_ec2" {
      + arn             = (known after apply)
      + fingerprint     = (known after apply)
      + id              = (known after apply)
      + key_name        = "vault-ssh-key"
      + key_name_prefix = (known after apply)
      + key_pair_id     = (known after apply)
      + key_type        = (known after apply)
      + public_key      = (known after apply)
      + tags_all        = (known after apply)
    }

  # aws_kms_alias.vault_kms will be created
  + resource "aws_kms_alias" "vault_kms" {
      + arn            = (known after apply)
      + id             = (known after apply)
      + name           = "alias/vault-kms"
      + name_prefix    = (known after apply)
      + target_key_arn = (known after apply)
      + target_key_id  = (known after apply)
    }

  # aws_kms_key.vault_kms will be created
  + resource "aws_kms_key" "vault_kms" {
      + arn                                = (known after apply)
      + bypass_policy_lockout_safety_check = false
      + customer_master_key_spec           = "SYMMETRIC_DEFAULT"
      + deletion_window_in_days            = 10
      + description                        = "Parameter Store KMS master key"
      + enable_key_rotation                = true
      + id                                 = (known after apply)
      + is_enabled                         = true
      + key_id                             = (known after apply)
      + key_usage                          = "ENCRYPT_DECRYPT"
      + multi_region                       = (known after apply)
      + tags                               = {
          + "Role"    = "vault"
          + "orgname" = "medium"
          + "owner"   = "alex"
          + "tier"    = "lower"
        }
      + tags_all                           = {
          + "Role"    = "vault"
          + "orgname" = "medium"
          + "owner"   = "alex"
          + "tier"    = "lower"
        }
    }

  # aws_s3_bucket.vault_s3 will be created
  + resource "aws_s3_bucket" "vault_s3" {
      + acceleration_status         = (known after apply)
      + acl                         = (known after apply)
      + arn                         = (known after apply)
      + bucket                      = (known after apply)
      + bucket_domain_name          = (known after apply)
      + bucket_prefix               = (known after apply)
      + bucket_regional_domain_name = (known after apply)
      + force_destroy               = false
      + hosted_zone_id              = (known after apply)
      + id                          = (known after apply)
      + object_lock_enabled         = (known after apply)
      + policy                      = (known after apply)
      + region                      = (known after apply)
      + request_payer               = (known after apply)
      + tags                        = {
          + "Role"    = "vault"
          + "orgname" = "medium"
          + "owner"   = "alex"
          + "tier"    = "lower"
        }
      + tags_all                    = {
          + "Role"    = "vault"
          + "orgname" = "medium"
          + "owner"   = "alex"
          + "tier"    = "lower"
        }
      + website_domain              = (known after apply)
      + website_endpoint            = (known after apply)

      + cors_rule {
          + allowed_headers = (known after apply)
          + allowed_methods = (known after apply)
          + allowed_origins = (known after apply)
          + expose_headers  = (known after apply)
          + max_age_seconds = (known after apply)
        }

      + grant {
          + id          = (known after apply)
          + permissions = (known after apply)
          + type        = (known after apply)
          + uri         = (known after apply)
        }

      + lifecycle_rule {
          + abort_incomplete_multipart_upload_days = (known after apply)
          + enabled                                = (known after apply)
          + id                                     = (known after apply)
          + prefix                                 = (known after apply)
          + tags                                   = (known after apply)

          + expiration {
              + date                         = (known after apply)
              + days                         = (known after apply)
              + expired_object_delete_marker = (known after apply)
            }

          + noncurrent_version_expiration {
              + days = (known after apply)
            }

          + noncurrent_version_transition {
              + days          = (known after apply)
              + storage_class = (known after apply)
            }

          + transition {
              + date          = (known after apply)
              + days          = (known after apply)
              + storage_class = (known after apply)
            }
        }

      + logging {
          + target_bucket = (known after apply)
          + target_prefix = (known after apply)
        }

      + object_lock_configuration {
          + object_lock_enabled = (known after apply)

          + rule {
              + default_retention {
                  + days  = (known after apply)
                  + mode  = (known after apply)
                  + years = (known after apply)
                }
            }
        }

      + replication_configuration {
          + role = (known after apply)

          + rules {
              + delete_marker_replication_status = (known after apply)
              + id                               = (known after apply)
              + prefix                           = (known after apply)
              + priority                         = (known after apply)
              + status                           = (known after apply)

              + destination {
                  + account_id         = (known after apply)
                  + bucket             = (known after apply)
                  + replica_kms_key_id = (known after apply)
                  + storage_class      = (known after apply)

                  + access_control_translation {
                      + owner = (known after apply)
                    }

                  + metrics {
                      + minutes = (known after apply)
                      + status  = (known after apply)
                    }

                  + replication_time {
                      + minutes = (known after apply)
                      + status  = (known after apply)
                    }
                }

              + filter {
                  + prefix = (known after apply)
                  + tags   = (known after apply)
                }

              + source_selection_criteria {
                  + sse_kms_encrypted_objects {
                      + enabled = (known after apply)
                    }
                }
            }
        }

      + server_side_encryption_configuration {
          + rule {
              + bucket_key_enabled = (known after apply)

              + apply_server_side_encryption_by_default {
                  + kms_master_key_id = (known after apply)
                  + sse_algorithm     = (known after apply)
                }
            }
        }

      + versioning {
          + enabled    = (known after apply)
          + mfa_delete = (known after apply)
        }

      + website {
          + error_document           = (known after apply)
          + index_document           = (known after apply)
          + redirect_all_requests_to = (known after apply)
          + routing_rules            = (known after apply)
        }
    }

  # aws_s3_bucket_public_access_block.vault_s3 will be created
  + resource "aws_s3_bucket_public_access_block" "vault_s3" {
      + block_public_acls       = true
      + block_public_policy     = true
      + bucket                  = (known after apply)
      + id                      = (known after apply)
      + ignore_public_acls      = true
      + restrict_public_buckets = true
    }

  # aws_s3_bucket_server_side_encryption_configuration.vault_s3 will be created
  + resource "aws_s3_bucket_server_side_encryption_configuration" "vault_s3" {
      + bucket = (known after apply)
      + id     = (known after apply)

      + rule {
          + apply_server_side_encryption_by_default {
              + sse_algorithm = "AES256"
            }
        }
    }

  # random_id.suffix will be created
  + resource "random_id" "suffix" {
      + b64_std     = (known after apply)
      + b64_url     = (known after apply)
      + byte_length = 4
      + dec         = (known after apply)
      + hex         = (known after apply)
      + id          = (known after apply)
    }

  # tls_private_key.vault_ec2 will be created
  + resource "tls_private_key" "vault_ec2" {
      + algorithm                     = "RSA"
      + ecdsa_curve                   = "P224"
      + id                            = (known after apply)
      + private_key_openssh           = (sensitive value)
      + private_key_pem               = (sensitive value)
      + private_key_pem_pkcs8         = (sensitive value)
      + public_key_fingerprint_md5    = (known after apply)
      + public_key_fingerprint_sha256 = (known after apply)
      + public_key_openssh            = (known after apply)
      + public_key_pem                = (known after apply)
      + rsa_bits                      = 4096
    }

Plan: 16 to add, 0 to change, 0 to destroy.

Changes to Outputs:
  + iam_access_key = (sensitive value)
  + iam_secret_key = (sensitive value)
  + kms_key_alias  = "alias/vault-kms"
  + private_key    = (sensitive value)
  + s3_bucket_name = (known after apply)

────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────────

Saved the plan to: /tmp/plan

To perform exactly these actions, run the following command to apply:
    terraform apply "/tmp/plan"
prompt> terraform apply /tmp/plan
random_id.suffix: Creating...
random_id.suffix: Creation complete after 0s [id=rOdEQw]
tls_private_key.vault_ec2: Creating...
aws_iam_user.vault_iam: Creating...
aws_kms_key.vault_kms: Creating...
aws_iam_role.vault_iam: Creating...
aws_s3_bucket.vault_s3: Creating...
aws_iam_user.vault_iam: Creation complete after 0s [id=vaultUser]
aws_iam_access_key.vault_iam: Creating...
tls_private_key.vault_ec2: Creation complete after 1s [id=ad67ad338849d1f2d02156d8a1114061c85047fd]
aws_key_pair.vault_ec2: Creating...
aws_iam_access_key.vault_iam: Creation complete after 0s [id=AKIAYYQBXQTWQLGMK3J5]
aws_iam_role.vault_iam: Creation complete after 0s [id=vaultIam]
aws_iam_role_policy_attachment.vault_iam: Creating...
aws_iam_instance_profile.vault_iam: Creating...
aws_iam_role_policy_attachment.vault_iam: Creation complete after 0s [id=vaultIam-20231113130837385400000001]
aws_key_pair.vault_ec2: Creation complete after 1s [id=vault-ssh-key]
aws_iam_instance_profile.vault_iam: Creation complete after 1s [id=vaultIam]
aws_instance.vault_ec2: Creating...
aws_s3_bucket.vault_s3: Creation complete after 2s [id=vaults3mediumace74443]
aws_s3_bucket_public_access_block.vault_s3: Creating...
aws_s3_bucket_server_side_encryption_configuration.vault_s3: Creating...
aws_s3_bucket_public_access_block.vault_s3: Creation complete after 0s [id=vaults3mediumace74443]
aws_s3_bucket_server_side_encryption_configuration.vault_s3: Creation complete after 1s [id=vaults3mediumace74443]
aws_kms_key.vault_kms: Creation complete after 9s [id=98527dd1-2510-4f09-95ac-4e7a0b32a2d2]
aws_kms_alias.vault_kms: Creating...
aws_iam_policy.vault_iam: Creating...
aws_kms_alias.vault_kms: Creation complete after 0s [id=alias/vault-kms]
aws_iam_policy.vault_iam: Creation complete after 0s [id=arn:aws:iam::602372801773:policy/vaultUser]
aws_iam_user_policy_attachment.vault_iam: Creating...
aws_iam_user_policy_attachment.vault_iam: Creation complete after 1s [id=vaultUser-20231113130846503400000003]
aws_instance.vault_ec2: Still creating... [10s elapsed]
aws_instance.vault_ec2: Still creating... [20s elapsed]
aws_instance.vault_ec2: Still creating... [30s elapsed]
aws_instance.vault_ec2: Still creating... [40s elapsed]
aws_instance.vault_ec2: Creation complete after 42s [id=i-030261b2da6339dbc]

Apply complete! Resources: 16 added, 0 changed, 0 destroyed.

Outputs:

iam_access_key = <sensitive>
iam_secret_key = <sensitive>
kms_key_alias = "alias/vault-kms"
private_key = <sensitive>
s3_bucket_name = "vaults3mediumace74443"
```

## Ansible: Bootstrapping Vault
Now that we have an EC2 instance, S3 bucket, and KMS keys,
we can bootstrap our vault server. To be clear, you could
have done this with a `remote_exec` provisioner in terraform.
I prefer to break up my terraform and ansible as I feel it gives
me a bit more flexibility in the event of urgent changes, adhoc fixes, 
etc. but both will work perfectly fine. Using ansible on its own
will also let us leverage dynamic inventories, which will be a fun topic!

Let's start with our `inventory` to see how to use the ansible dynamic inventory:

```yaml
# inventory/vault.aws_ec2.yml
plugin: aws_ec2

regions:
  - us-east-2

filters:
  tag:Role: vault
  instance-state-name: running

keyed_groups:
  - key: tags.Role
    separator: ""

hostnames:
  - instance-id
```

Looking at this, we can see that we are using the aws ec2 plugin. This plugin
will look in the `us-east-2` region for instances that are running and have
the tag of `Role:vault` which was added to our instances using terraform.
We then assign all of these hosts to a group where the group name will be the
value of `tags.Role` or, in our case, `vault`. So, moving forward, we will
be targetting the ansible hosts in the group `vault`. If you have any confusion, 
the `ansible-inventory -i inventory --list` command is extremely valuable in seeing
what your inventory looks like.

We can also look at our `group_vars` to see how ansible will be connecting
to our EC2 instance:

```yaml
# group_vars/vault.yml
ansible_ssh_common_args: -o StrictHostKeyChecking=no -o ProxyCommand="sh -c \"aws ssm start-session --target %h --document-name AWS-StartSSHSession --parameters 'portNumber=%p'\""
ansible_user: "ubuntu"
ansible_become: true
ansible_ssh_private_key_file: "/tmp/vault-ssh"
ansible_python_interpreter: "/usr/bin/python3"
```

Whoa - what is that `ansible_ssh_common_args` mess? This is what it looks like
to have SSM proxy your SSH traffic. You can see that, instead of invoking
SSH directly, we invoke it with the `AWS-StartSSHSession` action of the `aws ssm`
cli. Nice - no direct SSH connections and our isntance stays secure! We also
tell ansible to connect as the `ubuntu` user and give it the location to our
private SSH key, which was provisioned with terraform.

We can now get into the nitty-gritty of our ansible code. We will have two
task lists which we will import into our `site.yml`:

1. `tasks/apt.yml` - performs any apt actions, like adding new apt repos or keys.
2. `tasks/vault.yml` - performs any vault-related actions, like adding it as
  as systemd service, adding users/groups, setting up configs, etc.

I prefer to break up my tasks into task lists that way my top level playbook stays
squeaky clean. Let's look at the top level playbook below:

```yaml
#!/usr/bin/env ansible-playbook
---
- name: vault setup
  hosts: vault
  gather_facts: true

  tasks:
  
    - name: Run Apt Tasks
      include_tasks: ./tasks/apt.yml
    
    - name: Run Vault Tasks
      include_tasks: ./tasks/vault.yml
```

We can see we are targetting our `vault` hosts from our dynamic inventory.
We are then running our two task sets against these hosts. Let's look at
the `apt.yml` task list:

```yaml
- name: Add HashiCorp Apt Key
  become: true
  get_url:
    url: https://apt.releases.hashicorp.com/gpg
    dest: /usr/share/keyrings/hashicorp-archive-keyring.asc
  register: _download_key

- name: Add HashiCorp Apt Repo
  apt_repository:
    repo: "deb [signed-by={{ _download_key.dest }}] https://apt.releases.hashicorp.com {{ ansible_distribution_release }} main"
    state: present

- name: Install vault
  apt:
    name: vault
    update_cache: true
```

We see that we first add HashiCorps GPG APT key to our keyring by downloading
it from their website and putting it into Ubunutu's expected key location.
Next, we add the HashiCorp apt repo to our known list of repos - using the key
we downloaded above as our signing key. Finally, we can run the `apt update && apt install vault` simultaneously with the `apt` ansible action. As of now, we have the 
vault binary installed on the system and it just needs to be configured and started.

Let's pivot to look at the `vault.yml` task list:

```yml
- name: Ensure vault is installed
  shell: which vault
  register: _vault_bin

- name: Add Vault Group
  group: 
    name: vault
  register: _vault_group

- name: Add vault user
  user:
    name: vault
    groups: "{{ _vault_group.name }}"
    shell: /sbin/nologin
    create_home: no
    append: true
    comment: "Vault service user"
    state: present
  register: _vault_user
  
- name: Create vault config file
  template:
    src: templates/etc/vault.d/vault.hcl.j2
    dest: /etc/vault.d/vault.hcl
  vars:
    access_key: "{{ iam_access_key }}"
    secret_key: "{{ iam_secret_key }}"
    bucket: "{{ s3_bucket_name }}"
    kms_key_id: "{{ kms_key_alias }}"
    region: us-east-2
  register: _vault_config

- name: Create vault systemd file
  template:
    src: templates/etc/systemd/system/vault.service.j2
    dest: /etc/systemd/system/vault.service
  vars:
    vault_bin: "{{ _vault_bin.stdout }}"
    vault_config: "{{ _vault_config.dest }}"
    vault_user: "{{ _vault_user.name }}"
    vault_group: "{{ _vault_group.name }}"

- name: start vault
  systemd:
    state: started
    daemon_reload: true
    name: vault
```

The first thing we do is make sure the vault binary is installed.
It should be, but we want to see the full path of it and it acts as
a good sanity check. We will use this full path in one of our templates
in a coming task.

Next, we want to add a vault user and group to make sure that our 
linux system stays secure. We also enforce that our vault user
has no login capabilities - enforcing it as just a service role. Next,
we will template our vault config file. Let's look at the raw template below:

```hcl
disable_mlock = true
ui = true

listener "tcp" {
  tls_disable = 1
  address = "[::]:8200"
  cluster_address = "[::]:8201"
  telemetry = {
    unauthenticated_metrics_access = true
  }
}

telemetry {
  prometheus_retention_time = "30m"
  disable_hostname = true
}

storage "s3" {
  access_key = "{{ access_key }}"
  secret_key = "{{ secret_key }}"
  bucket     = "{{ bucket }}"
  kms_key_id = "{{ kms_key_id }}"
  region     = "{{ region }}"
}
```

This template is pretty standard, but the most important part is
the storage section. Note that all of the variables in here are 
pieces of infrastructure we deployed with terraform and will
tell our vault instance how to store things in S3.

Once the configuration is set, we can install the systemd service for vault 
onto the system below, again using templates. Let's look at the raw
template below:

```shell
[Unit]
Description="HashiCorp Vault - A tool for managing secrets" Documentation=https://www.vaultproject.io/docs/
Requires=network-online.target
After=network-online.target 
StartLimitBurst=3

[Service]
User={{ vault_user }}
Group={{ vault_group }}
ProtectSystem=full
ProtectHome=read-only
PrivateTmp=yes
PrivateDevices=yes
CapabilityBoundingSet=CAP_SYSLOG CAP_IPC_LOCK
NoNewPrivileges=yes
ExecStart={{ vault_bin }} server -config={{ vault_config }} 
ExecReload=/bin/kill --signal HUP $MAINPID 
KillMode=process 
KillSignal=SIGINT 
Restart=on-failure 
RestartSec=5
TimeoutStopSec=30
StartLimitInterval=60
StartLimitBurst=3
LimitNOFILE=65536
LimitMEMLOCK=infinity

[Install]
WantedBy=multi-user.target
```

This looks like a lot - but the most important sections are:

```shell
User={{ vault_user }}
Group={{ vault_group }}
ExecStart={{ vault_bin }} server -config={{ vault_config }} 
```

These three lines tell systemd to:

* start the process as the vault user and vault group
* run the vault command, in server mode, with the pre-templated config

Finally, we can start the systemd process, essentially starting up the server.

### Running Ansible
Now, we can run our ansible playbook!

```shell
# First, let's get some of the terraform outputs:
# Lets write our SSH key to a place where ansible can find it
terraform output -raw private_key > /tmp/vault-ssh
chmod 600 /tmp/vault-ssh

# Lets set the parameters for vault templating
iam_access_key=$(terraform output -raw iam_access_key)
iam_secret_key=$(terraform output -raw iam_secret_key)
s3_bucket_name=$(terraform output -raw s3_bucket_name)
kms_key_alias=$(terraform output -raw kms_key_alias)

cd ../ansible

poetry run ansible-playbook -i inventory site.yml -e iam_access_key="$iam_access_key" \
  -e iam_secret_key="$iam_secret_key" \
  -e s3_bucket_name="$s3_bucket_name "\
  -e kms_key_alias="$kms_key_alias" 
```

An example output will be something like the below:

```shell
prompt> poetry run ansible-playbook -i inventory site.yml -e iam_access_key="$iam_access_key" \
  -e iam_secret_key="$iam_secret_key" \
  -e s3_bucket_name="$s3_bucket_name "\
  -e kms_key_alias="$kms_key_alias"

PLAY [vault setup] ******************************************************************************************************************************************************************************

TASK [Gathering Facts] **************************************************************************************************************************************************************************
ok: [i-030261b2da6339dbc]

TASK [Run Apt Tasks] ****************************************************************************************************************************************************************************
included: /Users/alexanderfoley/mycode/vault-ansible-terraform/ansible/tasks/apt.yml for i-030261b2da6339dbc

TASK [Add HashiCorp Apt Key] ********************************************************************************************************************************************************************
changed: [i-030261b2da6339dbc]

TASK [Add HashiCorp Apt Repo] *******************************************************************************************************************************************************************
changed: [i-030261b2da6339dbc]

TASK [Install vault] ****************************************************************************************************************************************************************************
changed: [i-030261b2da6339dbc]

TASK [Run Vault Tasks] **************************************************************************************************************************************************************************
included: /Users/alexanderfoley/mycode/vault-ansible-terraform/ansible/tasks/vault.yml for i-030261b2da6339dbc

TASK [Ensure vault is installed] ****************************************************************************************************************************************************************
changed: [i-030261b2da6339dbc]

TASK [Add Vault Group] **************************************************************************************************************************************************************************
ok: [i-030261b2da6339dbc]

TASK [Add vault user] ***************************************************************************************************************************************************************************
changed: [i-030261b2da6339dbc]

TASK [Create vault config file] *****************************************************************************************************************************************************************
changed: [i-030261b2da6339dbc]

TASK [Create vault systemd file] ****************************************************************************************************************************************************************
changed: [i-030261b2da6339dbc]

TASK [start vault] ******************************************************************************************************************************************************************************
changed: [i-030261b2da6339dbc]

PLAY RECAP **************************************************************************************************************************************************************************************
i-030261b2da6339dbc        : ok=12   changed=8    unreachable=0    failed=0    skipped=0    rescued=0    ignored=0   

prompt>
```

Now, let's visit our vault UI! First, we will proxy our traffic through SSM using the below command:

```shell
aws ssm start-session \
    --target <your-instance-id> \
    --document-name AWS-StartPortForwardingSession \
    --parameters '{"portNumber":["8200"], "localPortNumber":["8200"]}'
```

Now, we can navigate to `localhost:8200` in a browser to see our vault instance!

![Vault Instance](./images/vault-browser.png)

## Cleaning up
If you're trying to stay on the free-tier like me, don't forget to run a `terraform destroy`
after you're done poking around!

## References
Please feel free to poke around my [github repo](https://github.com/afoley587/vault-terraform-ansible) for full code!