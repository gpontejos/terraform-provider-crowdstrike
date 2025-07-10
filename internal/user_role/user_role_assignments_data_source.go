package userrole

import (
	"context"
	"fmt"
	"strings"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/sensor_download"
	"github.com/crowdstrike/gofalcon/falcon/client/user_management"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &userRoleAssignmentDataSource{}
	_ datasource.DataSourceWithConfigure = &userRoleAssignmentDataSource{}
)

var (
	documentationSection        string         = "section"
	resourceMarkdownDescription string         = "<description>"
	requiredScopes              []scopes.Scope = []scopes.Scope{}
	recordReturnLimit           int64          = 500
)

func NewUserRoleAssignmentDataSource() datasource.DataSource {
	return &userRoleAssignmentDataSource{}
}

type userRoleAssignmentDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type userRoleAssignmentDataSourceModel struct {
	UUID            types.String `tfsdk:"uuid"`
	CID             types.String `tfsdk:"cid"`
	AssignedRoleIds types.List   `tfsdk:"assigned_role_ids"`
}

func (r *userRoleAssignmentDataSource) Configure(
	ctx context.Context,
	req datasource.ConfigureRequest,
	resp *datasource.ConfigureResponse,
) {
	if req.ProviderData == nil {
		return
	}

	client, ok := req.ProviderData.(*client.CrowdStrikeAPISpecification)

	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected Resource Configure Type",
			fmt.Sprintf(
				"Expected *client.CrowdStrikeAPISpecification, got: %T. Please report this issue to the provider developers.",
				req.ProviderData,
			),
		)

		return
	}

	r.client = client
}

func (r *userRoleAssignmentDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_user_role_assignments"
}

func (r *userRoleAssignmentDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, resourceMarkdownDescription, requiredScopes),
		Attributes: map[string]schema.Attribute{
			"uuid": schema.StringAttribute{
				Required:    true,
				Description: "The UUID of the user that the roles are assigned to",
			},
			"cid": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The CID of the user at the roles are assigned to",
			},
			"assigned_role_ids": schema.ListAttribute{
				Computed:    true,
				ElementType: types.StringType,
				Description: "List of roles assigned to the user",
			},
		},
	}
}

func (r *userRoleAssignmentDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data userRoleAssignmentDataSourceModel
	var roles *[]string
	var rolesList types.List
	var diags diag.Diagnostics

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	cid := data.CID.ValueStringPointer()
	if cid == nil {
		cid, diags = r.getCid(ctx)
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
			return
		}

	}

	roles, diags = r.getAssignedRoles(ctx, data.UUID.String(), cid)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	rolesList, diags = types.ListValueFrom(ctx, types.StringType, roles)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	data.AssignedRoleIds = rolesList
	data.CID = types.StringValue(*cid)

	// Set State
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *userRoleAssignmentDataSource) getAssignedRoles(
	ctx context.Context,
	uuid string,
	cid *string,
) (*[]string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var roles []string

	params := user_management.CombinedUserRolesV2Params{
		Context:  ctx,
		UserUUID: strings.Trim(uuid, "\""),
		Limit:    &recordReturnLimit,
		Cid:      cid,
	}

	resp, err := r.client.UserManagement.CombinedUserRolesV2(&params)
	if err != nil {
		if _, ok := err.(*user_management.CombinedUserRolesV2Forbidden); ok {
			diags.AddError(
				"Failed to read assigned roles for individual user :: 403 Forbidden",
				scopes.GenerateScopeDescription(userRoleScopes),
			)
			return nil, diags
		}
		diags.AddError(
			"Failed to read assigned roles for user",
			fmt.Sprintf("Failed to read assigned roles for user: %s", err.Error()),
		)
		return nil, diags
	}

	for _, resource := range resp.Payload.Resources {
		roles = append(roles, *resource.RoleID)
	}

	return &roles, diags
}

func (r *userRoleAssignmentDataSource) getCid(
	ctx context.Context,
) (*string, diag.Diagnostics) {
	var diags diag.Diagnostics
	var cid string

	params := &sensor_download.GetSensorInstallersCCIDByQueryParams{
		Context: ctx,
	}

	resp, err := r.client.SensorDownload.GetSensorInstallersCCIDByQuery(params)

	if err != nil {
		if _, ok := err.(*sensor_download.GetSensorInstallersCCIDByQueryForbidden); ok {
			diags.AddError(
				"Failed to get CID from API credentials :: 403 Forbidden",
				scopes.GenerateScopeDescription(getCidScopes),
			)
			return nil, diags
		}

		return nil, diags
	}
	payload := resp.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to get CID from API credentials",
			fmt.Sprintf("Error reported when getting CCID from CrowdStrike Falcon API: %s", err.Error()),
		)
		return nil, diags
	}
	if len(payload.Resources) != 1 {
		diags.AddError(
			"Failed to get CID from API credentials",
			fmt.Sprintf("Failed to get CCID: Unexpected API response %s", payload.Resources),
		)
		return nil, diags
	}

	cid = strings.Split(payload.Resources[0], "-")[0]

	return &cid, diags
}
