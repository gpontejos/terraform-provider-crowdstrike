package functions_test

import (
	"fmt"
	"regexp"
	"strings"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

type testCrnCloudConfig struct {
	cloudProvider string
	account       string
	region        string
	resourceType  string
	resourceId    string
}

var (
	awsConfig = testCrnCloudConfig{
		cloudProvider: "aws",
		account:       "123456789012",
		region:        "us-east-1",
		resourceType:  "EC2",
		resourceId:    "arn:aws:ec2:us-east-1:123456789012:instance/i-1234567890abcdef0",
	}
	azureConfig = testCrnCloudConfig{
		cloudProvider: "azure",
		account:       "12345678-1234-1234-1234-123456789012",
		region:        "eastus",
		resourceType:  "Virtual Machines",
		resourceId:    "/subscriptions/12345678-1234-1234-1234-123456789012/resourceGroups/my-rg/providers/Microsoft.Compute/virtualMachines/my-vm",
	}
	gcpConfig = testCrnCloudConfig{
		cloudProvider: "gcp",
		account:       "my-test-project",
		region:        "us-central1-a",
		resourceType:  "Compute",
		resourceId:    "projects/my-test-project/zones/us-central1-a/instances/my-instance",
	}
)

func TestGenerateCrnFunction(t *testing.T) {
	var steps []resource.TestStep
	t.Parallel()

	steps = append(steps, testBuildCrnCombinedTests(awsConfig)...)
	steps = append(steps, testBuildCrnCombinedTests(azureConfig)...)
	steps = append(steps, testBuildCrnCombinedTests(gcpConfig)...)

	resource.UnitTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		Steps:                    steps,
	})
}

func testBuildCrnCombinedTests(config testCrnCloudConfig) []resource.TestStep {
	testSteps := []resource.TestStep{}

	// switch config.cloudProvider {
	// case "aws":
	// 	testSteps = append(testSteps, resource.TestStep{
	// 		Config:      testBuildCrnResourceInvalidResourceId(config),
	// 		ExpectError: regexp.MustCompile(`Invalid\s+AWS\s+ARN\s+format\s+for\s+resource_id`),
	// 	})
	// case "azure":
	// 	testSteps = append(testSteps, resource.TestStep{
	// 		Config:      testBuildCrnResourceInvalidResourceId(config),
	// 		ExpectError: regexp.MustCompile(`Invalid\s+Azure\s+resource\s+ID\s+format\s+for\s+resource_id`),
	// 	})
	// case "gcp":
	// 	testSteps = append(testSteps, resource.TestStep{
	// 		Config:      testBuildCrnResourceInvalidResourceId(config),
	// 		ExpectError: regexp.MustCompile(`Invalid\s+GCP\s+resource\s+ID\s+format\s+for\s+resource_id`),
	// 	})
	// }

	testSteps = append(testSteps, []resource.TestStep{
		{
			Config: testBuildCrnResource(config),
			Check: resource.ComposeAggregateTestCheckFunc(
				resource.TestCheckOutput(config.cloudProvider, testBuildCrnOutput(config)),
			),
		},
		{
			Config:      testBuildCrnResourceInvalidCloudProvider(config),
			ExpectError: regexp.MustCompile(`value\s+must\s+be\s+one\s+of:\s+\[\"aws\"\s+\"gcp\"\s+\"azure\"\],\s+got:\s+\"invalid\"`),
		},
		{
			Config:      testBuildCrnResourceEmptyAccount(config),
			ExpectError: regexp.MustCompile("account cannot be empty"),
		},
		{
			Config:      testBuildCrnResourceEmptyRegion(config),
			ExpectError: regexp.MustCompile("region cannot be empty"),
		},
		{
			Config:      testBuildCrnResourceEmptyResourceType(config),
			ExpectError: regexp.MustCompile("resource_type cannot be empty"),
		},
		{
			Config:      testBuildCrnResourceEmptyResourceId(config),
			ExpectError: regexp.MustCompile("resource_id cannot be empty"),
		},
	}...)

	return testSteps
}

func testBuildCrnResource(config testCrnCloudConfig) string {
	return fmt.Sprintf(`
output "%[1]s" {
  value = provider::crowdstrike::generate_crn("%[1]s", "%[2]s", "%[3]s", "%[4]s", "%[5]s")
}`, config.cloudProvider, config.account, config.region, config.resourceType, config.resourceId)
}

func testBuildCrnResourceInvalidCloudProvider(config testCrnCloudConfig) string {
	return fmt.Sprintf(`
output "%[1]s" {
  value = provider::crowdstrike::generate_crn("invalid", "%[2]s", "%[3]s", "%[4]s", "%[5]s")
}`, config.cloudProvider, config.account, config.region, config.resourceType, config.resourceId)
}

func testBuildCrnResourceEmptyAccount(config testCrnCloudConfig) string {
	return fmt.Sprintf(`
output "%[1]s" {
  value = provider::crowdstrike::generate_crn("%[1]s", "", "%[2]s", "%[3]s", "%[4]s")
}`, config.cloudProvider, config.region, config.resourceType, config.resourceId)
}

func testBuildCrnResourceEmptyRegion(config testCrnCloudConfig) string {
	return fmt.Sprintf(`
output "%[1]s" {
  value = provider::crowdstrike::generate_crn("%[1]s", "%[2]s", "", "%[3]s", "%[4]s")
}`, config.cloudProvider, config.account, config.resourceType, config.resourceId)
}

func testBuildCrnResourceEmptyResourceType(config testCrnCloudConfig) string {
	return fmt.Sprintf(`
output "%[1]s" {
  value = provider::crowdstrike::generate_crn("%[1]s", "%[2]s", "%[3]s", "", "%[4]s")
}`, config.cloudProvider, config.account, config.region, config.resourceId)
}

func testBuildCrnResourceEmptyResourceId(config testCrnCloudConfig) string {
	return fmt.Sprintf(`
output "%[1]s" {
  value = provider::crowdstrike::generate_crn("%[1]s", "%[2]s", "%[3]s", "%[4]s", "")
}`, config.cloudProvider, config.account, config.region, config.resourceType)
}

// func testBuildCrnResourceInvalidResourceId(config crnCloudConfig) string {
// 	return fmt.Sprintf(`
// output "%[1]s" {
//   value = provider::crowdstrike::generate_crn("%[1]s", "%[2]s", "%[3]s", "%[4]s", "invalid")
// }`, config.cloudProvider, config.account, config.region, config.resourceType)
// }

func testBuildCrnOutput(config testCrnCloudConfig) string {
	return strings.Join([]string{
		config.cloudProvider,
		config.account,
		config.region,
		config.resourceType,
		config.resourceId,
	}, "|")
}
