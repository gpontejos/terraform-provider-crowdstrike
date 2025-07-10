package userrole_test

import (
	"fmt"
	"os"
	"testing"

	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/acctest"
	"github.com/hashicorp/terraform-plugin-testing/helper/resource"
)

var (
	testFalconCID = "" // This needs to be the CID without the -XX
	TestUuid      = "" // uuid for an individual user
)

func TestUserRoleAssignmentDataSource(t *testing.T) {
	dataSourceNameWithCID := "data.crowdstrike_user_role_assignments.withCID"
	dataSourceNameWithoutCID := "data.crowdstrike_user_role_assignments.withoutCID"

	resource.ParallelTest(t, resource.TestCase{
		ProtoV6ProviderFactories: acctest.ProtoV6ProviderFactories,
		PreCheck:                 func() { preCheck(t) },
		Steps: []resource.TestStep{
			// Test data source when CID is passed
			{
				Config: testUserRoleAssignmentDataSource_withCID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceNameWithCID, "assigned_role_ids.#"),
					resource.TestCheckResourceAttrSet(dataSourceNameWithCID, "uuid"),
					resource.TestCheckResourceAttrSet(dataSourceNameWithCID, "cid"),
				),
			},
			// Test data source when CID is queried
			{
				Config: testUserRoleAssignmentDataSource_withoutCID(),
				Check: resource.ComposeAggregateTestCheckFunc(
					resource.TestCheckResourceAttrSet(dataSourceNameWithoutCID, "assigned_role_ids.#"),
					resource.TestCheckResourceAttrSet(dataSourceNameWithoutCID, "uuid"),
					// resource.TestCheckResourceAttrSet(dataSourceNameWithoutCID, "cid"),
				),
			},
		},
	})
}

func testUserRoleAssignmentDataSource_withCID() string {
	return fmt.Sprintf(`
data "crowdstrike_user_role_assignments" "withCID" {
  uuid = "%s"
  cid = "%s"
}
`, TestUuid, testFalconCID)
}

func testUserRoleAssignmentDataSource_withoutCID() string {
	return fmt.Sprintf(`
data "crowdstrike_user_role_assignments" "withoutCID" {
  uuid = "%s"
}
`, TestUuid)
}

func preCheck(t *testing.T) {
	requiredEnvVars := []string{
		"FALCON_CLIENT_ID",
		"FALCON_CLIENT_SECRET",
	}
	for _, envVar := range requiredEnvVars {
		if v := os.Getenv(envVar); v == "" {
			t.Fatalf("%s must be set for acceptance tests", envVar)
		}
	}
}
