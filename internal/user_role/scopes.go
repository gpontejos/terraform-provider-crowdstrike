package userrole

import "github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"

var userRoleScopes = []scopes.Scope{
	{
		Name:  "User management",
		Read:  true,
		Write: false,
	},
}

var getCidScopes = []scopes.Scope{
	{
		Name:  "Sensor Download",
		Read:  true,
		Write: false,
	},
}
