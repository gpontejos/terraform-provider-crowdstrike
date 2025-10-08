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

# create a rule override that silences a specific Cloud Asset
data "crowdstrike_cloud_posture_rules" "rule" {
  cloud_provider = "AWS"
  rule_name      = "IAM Customer Managed policy allows all kms actions"
}

resource "crowdstrike_cloud_posture_rule_override" "test" {
  rule_id       = data.crowdstrike_cloud_posture_rules.all.rules.*.id[0]
  override_type = "suppression"
  crn           = provider::crowdstrike::generate_crn("aws", "123456789012", "global", "AWS::IAM::UserPolicy", "arn:aws:iam::987654321098:role/ExampleRule2")
  expires_at    = "2026-10-06T21:33:11.929Z"
  depends_on    = [data.crowdstrike_cloud_posture_rules.rule]
}

# create a rule override that disables a rule
data "crowdstrike_cloud_posture_rules" "rule" {
  cloud_provider = "Azure"
  rule_name      = "AKS Cluster RBAC Disableds"
}

resource "crowdstrike_cloud_posture_rule_override" "test" {
  rule_id       = data.crowdstrike_cloud_posture_rules.all.rules.*.id[0]
  override_type = "suppression"
  crn           = provider::crowdstrike::generate_crn("Azure", "00000000-0000-0000-0000-000000000000", "eastus", "Microsoft.ContainerService/managedClusters", "/subscriptions/00000000-0000-0000-0000-000000000000/resourceGroups/myResourceGroup/providers/Microsoft.ContainerService/managedClusters/myAKSCluster")
  expires_at    = "2026-10-06T21:33:11.929Z"
  depends_on    = [data.crowdstrike_cloud_posture_rules.rule]
}
