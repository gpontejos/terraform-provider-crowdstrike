package cloudposture_test

// Check empty fields.
// Check nil
// Check from defined to empty or nil. In-place updates.

import (
	"fmt"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
	"github.com/hashicorp/terraform-plugin-testing/terraform"
)

type testRuleOverrideConfig struct {
	ruleName      string
	cloudProvider string
	expiresAt     []string
	crn           []string
	overrideType  string
}

var (
	suppressionConfig = testRuleOverrideConfig{
		ruleName: "IAM Customer Managed policy allows all kms actions",
		expiresAt: []string{
			"2029-10-06T21:33:11.929Z",
			"2030-10-06T21:33:11.929Z",
		},
		cloudProvider: "AWS",
		crn: []string{
			"aws|123456789012|global|AWS::IAM::UserPolicy|arn:aws:iam::987654321098:role/ExampleRole",
			"aws|123456789012|global|AWS::IAM::UserPolicy|arn:aws:iam::987654321098:role/ExampleRule2",
		},
		overrideType: "suppression",
	}

	// disableConfig = testRuleOverrideConfig{
	// 	ruleName: "Authentication via PowerShell/CLI",
	// 	expiresAt: []string{
	// 		"2028-10-06T21:33:11.929Z",
	// 		"2027-10-06T21:33:11.929Z",
	// 	},
	// 	cloudProvider: "Azure",
	// 	overrideType:  "disable",
	// }
)

func TestCloudPostureRuleOverrideResource(t *testing.T) {
	var steps []resource.TestStep

	for i := range 2 {
		resourceName := "crowdstrike_cloud_posture_rule_override." + suppressionConfig.overrideType
		resourceStep := resource.TestStep{
			Config: fmt.Sprintf(`
data "crowdstrike_cloud_posture_rules" "all" {
  cloud_provider = "%[1]s"
  rule_name = "%[2]s"
}

resource "crowdstrike_cloud_posture_rule_override" "%[3]s" {
    rule_id = data.crowdstrike_cloud_posture_rules.all.rules.*.id[0]
    override_type = "%[3]s"
    crn = "%[4]s"
    expires_at = "%[5]s"
    depends_on = [ data.crowdstrike_cloud_posture_rules.all ]
}
`, suppressionConfig.cloudProvider, suppressionConfig.ruleName, suppressionConfig.overrideType, suppressionConfig.crn[i],
				suppressionConfig.expiresAt[i]),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckResourceAttr(resourceName, "override_type", suppressionConfig.overrideType),
				resource.TestCheckResourceAttr(resourceName, "crn", suppressionConfig.crn[i]),
				resource.TestCheckResourceAttr(resourceName, "expires_at", suppressionConfig.expiresAt[i]),
				resource.TestCheckResourceAttrSet(resourceName, "rule_id"),
				resource.TestCheckResourceAttrSet(resourceName, "id"),
			),
		}

		importTestStep := resource.TestStep{
			ResourceName:                         resourceName,
			ImportState:                          true,
			ImportStateVerify:                    true,
			ImportStateVerifyIdentifierAttribute: "id",
			ImportStateIdFunc: func(s *terraform.State) (string, error) {
				rs, ok := s.RootModule().Resources[resourceName]
				if !ok {
					return "", fmt.Errorf("Resource not found: %s", resourceName)
				}
				return rs.Primary.Attributes["id"], nil
			},
		}

		steps = append(steps, resourceStep)
		steps = append(steps, importTestStep)

	}

	steps = append(steps, generateRuleCopyTests(awsCopyConfig, "AWS")...)
	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { acctest.PreCheck(t) },
		Steps:                    steps,
	})
}
