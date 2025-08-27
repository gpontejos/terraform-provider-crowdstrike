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


resource "crowdstrike_policy_rule" "example" {}

output "policy_rule" {
  value = crowdstrike_policy_rule.example
}
