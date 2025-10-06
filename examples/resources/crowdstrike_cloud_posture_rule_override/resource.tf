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


resource "crowdstrike_cloud_posture_rule_override" "example" {}

output "crowdstrike_cloud_posture_rule_override" {
  value = crowdstrike_cloud_posture_rule_override.example
}
