terraform {
  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 3.0"
    }
  }
}

# Configure the AWS Provider

provider "aws" {
  region     = "us-east-1"

  # .aws/credentials
  profile = "default"

  # access_key = "ACCESSKEY"
  # secret_key = "SECRETKEY"
  # token      = "SESSIONTOKEN"
}

