# One Dollar Devops: Deploying HashiVault With Terraform + Ansible

In the ever-evolving landscape of cloud computing, securing sensitive 
information and managing access credentials are paramount challenges 
for organizations. HashiCorp Vault emerges as a robust solution, 
providing a comprehensive platform for managing secrets, encryption 
keys, and other sensitive data across dynamic infrastructure. In this 
blog post, we will delve into the intricate world of deploying HashiCorp 
Vault on the AWS cloud using two powerful automation tools: Terraform and Ansible.

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