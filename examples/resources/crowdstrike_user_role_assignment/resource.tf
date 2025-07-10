terraform {
  required_providers {
    crowdstrike = {
      source = "registry.terraform.io/crowdstrike/crowdstrike"
    }
  }
}

provider "crowdstrike" {
  cloud = "us-2"
}


data "crowdstrike_user_role_assignment" "example" {}

output "user_role_assignment" {
  value = crowdstrike_user_role_assignment.example
}
