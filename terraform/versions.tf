terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "= 5.25.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "= 3.1.0"
    }
    tls = {
      source  = "hashicorp/tls"
      version = "= 4.0.4"
    }
  }
}