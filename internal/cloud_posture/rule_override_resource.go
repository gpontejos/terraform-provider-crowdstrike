package cloudposture

import (
	"context"
	"fmt"
	"log"
	"regexp"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/go-openapi/strfmt"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-log/tflog"
)

var (
	_ resource.Resource                   = &CrowdstrikeCloudPostureRuleOverrideResource{}
	_ resource.ResourceWithConfigure      = &CrowdstrikeCloudPostureRuleOverrideResource{}
	_ resource.ResourceWithImportState    = &CrowdstrikeCloudPostureRuleOverrideResource{}
	_ resource.ResourceWithValidateConfig = &CrowdstrikeCloudPostureRuleOverrideResource{}
	// _ resource.ResourceWithConfigValidators = &CrowdstrikeCloudPostureRuleOverrideResource{}
)

func NewCrowdstrikeCloudPostureRuleOverrideResource() resource.Resource {
	return &CrowdstrikeCloudPostureRuleOverrideResource{}
}

type CrowdstrikeCloudPostureRuleOverrideResource struct {
	client *client.CrowdStrikeAPISpecification
}

type CrowdstrikeCloudPostureRuleOverrideResourceModel struct {
	ID           types.String `tfsdk:"id"`
	ExpiresAt    types.String `tfsdk:"expires_at"`
	RuleId       types.String `tfsdk:"rule_id"`
	CRN          types.String `tfsdk:"crn"`
	OverrideType types.String `tfsdk:"override_type"`
}

func (m *CrowdstrikeCloudPostureRuleOverrideResourceModel) wrap(
	resp *models.ApimodelsRuleOverride,
) diag.Diagnostics {
	var diags diag.Diagnostics

	m.ID = types.StringPointerValue(resp.UUID)

	m.RuleId = types.StringValue(resp.RuleID)
	m.CRN = types.StringPointerValue(resp.Crn)
	m.OverrideType = types.StringPointerValue(resp.OverrideType)

	if resp.ExpiresAt == nil {
		diags.AddError(
			"Missing Expiration Timestamp",
			"The API response did not contain an expiration timestamp",
		)
	} else {
		m.ExpiresAt = types.StringValue(resp.ExpiresAt.String())
	}

	return diags
}

func (r *CrowdstrikeCloudPostureRuleOverrideResource) Configure(
	ctx context.Context,
	req resource.ConfigureRequest,
	resp *resource.ConfigureResponse,
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

func (r *CrowdstrikeCloudPostureRuleOverrideResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_posture_rule_override"
}

func (r *CrowdstrikeCloudPostureRuleOverrideResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Cloud Posture",
			"This resource creates overrides for cloud policy rules to temporarily or indefinitely disable specific rules.",
			cloudPostureRuleScopes,
		),
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Identifier for the Crowdstrike Cloud Posture Custom Rule Override.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
						"must be a valid Id in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"expires_at": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Expiration timestamp for the rule override. If expired, subsequent Terraform operations on this resource will fail until either removed or updated.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^([0-9]+)-(0[1-9]|1[012])-(0[1-9]|[12][0-9]|3[01])[Tt]([01][0-9]|2[0-3]):([0-5][0-9]):([0-5][0-9]|60)(\.[0-9]+)?(([Zz])|([+|-]([01][0-9]|2[0-3]):[0-5][0-9]))$`),
						"must be a valid RFC3339 timestamp",
					),
				},
			},
			"rule_id": schema.StringAttribute{
				Required:    true,
				Description: "The ID of the rule that will be silenced.",
			},
			"crn": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The CrowdStrike Resource Name (CRN) of the resource. This is the globally unique identifier for a given CrowdStrike CSPM resource",
				Default:     stringdefault.StaticString(""),
			},
			"override_type": schema.StringAttribute{
				Required:            true,
				MarkdownDescription: "The type of override to be performed. `suppression` applies an override to a specific CRN, while `disable` completely skips the rule evaluation.",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"suppression",
						"disable",
					),
				},
			},
		},
	}
}

func (r *CrowdstrikeCloudPostureRuleOverrideResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan CrowdstrikeCloudPostureRuleOverrideResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	ruleId, diags := r.createRuleOverride(
		ctx,
		plan.ExpiresAt.ValueString(),
		plan.OverrideType.ValueString(),
		plan.RuleId.ValueString(),
		plan.CRN.ValueString(),
	)

	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	resp.Diagnostics.Append(plan.wrap(ruleId)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *CrowdstrikeCloudPostureRuleOverrideResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state CrowdstrikeCloudPostureRuleOverrideResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	if state.OverrideType.ValueString() == "suppression" {
		if expired, diags := isTimestampExpired(state.ExpiresAt.ValueString()); expired {
			if diags.HasError() {
				resp.Diagnostics.Append(diags...)
			}
			resp.State.RemoveResource(ctx)
			resp.Diagnostics.AddWarning(
				"Rule Override Expired",
				fmt.Sprintf("The resource override with ID %s has expired and will be removed from the Terraform state.", state.ID.ValueString()),
			)
			return
		}
	}

	getOverride, diags := r.getRuleOverride(ctx, state.ID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}

	resp.Diagnostics.Append(state.wrap(getOverride)...)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *CrowdstrikeCloudPostureRuleOverrideResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan CrowdstrikeCloudPostureRuleOverrideResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	ruleId, diags := r.updateRuleOverride(
		ctx,
		plan.ExpiresAt.ValueString(),
		plan.OverrideType.ValueString(),
		plan.RuleId.ValueString(),
		plan.CRN.ValueString(),
	)

	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	plan.ID = types.StringValue(ruleId)
	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *CrowdstrikeCloudPostureRuleOverrideResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state CrowdstrikeCloudPostureRuleOverrideResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.deleteRuleOverride(ctx, state.ID.ValueString())...)
}

func (r *CrowdstrikeCloudPostureRuleOverrideResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

func (r *CrowdstrikeCloudPostureRuleOverrideResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config CrowdstrikeCloudPostureRuleOverrideResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

	if !config.CRN.IsUnknown() && !config.OverrideType.IsUnknown() {
		if !config.CRN.IsNull() && config.CRN.ValueString() != "" && config.OverrideType.ValueString() == "disable" {
			resp.Diagnostics.AddError(
				"Invalid Configuration",
				"CRN cannot be specified when override_type is set to 'disable'.",
			)
		}

		if config.OverrideType.ValueString() == "suppression" && !config.CRN.IsUnknown() && config.CRN.ValueString() == "" {
			if config.CRN.IsNull() {
				resp.Diagnostics.AddError(
					"Invalid Configuration",
					"CRN must be specified when override_type is set to 'suppression'.",
				)
			}
		}

		if !config.ExpiresAt.IsNull() && !config.ExpiresAt.IsUnknown() {
			if expired, diags := isTimestampExpired(config.ExpiresAt.ValueString()); expired {
				if diags.HasError() {
					resp.Diagnostics.Append(diags...)
				}
				resp.Diagnostics.AddError(
					"Expired Timestamp",
					fmt.Sprintf("The provided expiration timestamp (%s) has already passed.", config.ExpiresAt.ValueString()),
				)
			}
		}
	}
}

func (r *CrowdstrikeCloudPostureRuleOverrideResource) getRuleOverride(ctx context.Context, id string) (*models.ApimodelsRuleOverride, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := cloud_policies.GetRuleOverrideParams{
		Context: ctx,
		Ids:     []string{id},
	}

	resp, err := r.client.CloudPolicies.GetRuleOverride(&params)
	if err != nil {
		if notFound, ok := err.(*cloud_policies.GetRuleOverrideNotFound); ok {
			diags.AddError(
				"Error Retrieving Rule Override",
				fmt.Sprintf("Failed to retrieve rule override (404): %s, %+v", id, *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.GetRuleOverrideInternalServerError); ok {
			diags.AddError(
				"Error Retrieving Rule Override",
				fmt.Sprintf("Failed to retrieve rule override (500): %s, %+v", id, *internalServerError.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Retrieving Rule Override",
			fmt.Sprintf("Failed to retrieve rule override %s: %+v", id, err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Retrieving Rule Override",
			"Failed to retrieve rule override: Payload is empty.",
		)
		return nil, diags
	}

	resource := resp.GetPayload()
	log.Printf("Response: %+v", resource.Resources[0])

	return resource.Resources[0], diags
}

func (r *CrowdstrikeCloudPostureRuleOverrideResource) createRuleOverride(
	ctx context.Context,
	expiration string,
	overrideType string,
	ruleId string,
	crn string,
) (*models.ApimodelsRuleOverride, diag.Diagnostics) {
	var diags diag.Diagnostics
	params := cloud_policies.CreateRuleOverrideParams{
		Context: ctx,
		Body: &models.CommonCreateRuleOverrideRequest{
			Overrides: []*models.CommonSingleCreateRuleOverrideRequest{
				{
					OverrideType: &overrideType,
					RuleID:       &ruleId,
				},
			},
		},
	}

	if expiration != "" {
		convertedExpiration, diags := convertToRFC3339(expiration)
		if diags.HasError() {
			return nil, diags
		}
		params.Body.Overrides[0].ExpiresAt = convertedExpiration
	}

	if crn != "" {
		params.Body.Overrides[0].Crn = &crn
	}

	resp, err := r.client.CloudPolicies.CreateRuleOverride(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.CreateRuleOverrideBadRequest); ok {
			diags.AddError(
				"Error Creating Rule Override",
				fmt.Sprintf("Failed to create rule override (400): %s, %+v", ruleId, *badRequest.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if internalServerError, ok := err.(*cloud_policies.CreateRuleOverrideInternalServerError); ok {
			diags.AddError(
				"Error Creating Rule Override",
				fmt.Sprintf("Failed to create rule override (500): %s, %+v", ruleId, *internalServerError.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Creating Rule Override",
			fmt.Sprintf("Failed to retrieve rule override %s: %+v", ruleId, err),
		)

		return nil, diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Creating Rule Override",
			"Failed to create rule override: Payload is empty.",
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Creating Rule. Body Error",
			fmt.Sprintf("Failed to create rule: %s", err.Error()),
		)
		return nil, diags
	}

	// We need to get the rule prior to Read() due to default expiresAt timestamps being created
	getOverride, diags := r.getRuleOverride(ctx, payload.Resources[0])
	if diags.HasError() {
		return nil, diags
	}

	return getOverride, diags
}

func (r *CrowdstrikeCloudPostureRuleOverrideResource) deleteRuleOverride(ctx context.Context, id string) diag.Diagnostics {
	var diags diag.Diagnostics

	params := cloud_policies.DeleteRuleOverrideParams{
		Context: ctx,
		Ids:     []string{id},
	}

	_, _, err := r.client.CloudPolicies.DeleteRuleOverride(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.DeleteRuleOverrideBadRequest); ok {
			diags.AddError(
				"Error Deleting Rule Override",
				fmt.Sprintf("Failed to create rule override (400): %s, %+v", id, *badRequest.Payload.Errors[0].Message),
			)
			return diags
		}

		if notFound, ok := err.(*cloud_policies.DeleteRuleOverrideNotFound); ok {
			tflog.Info(ctx, "Rule Override Not Found", map[string]interface{}{
				"info": fmt.Sprintf("Rule override not found (404): %s, %+v", id, *notFound.Payload.Errors[0].Message),
			})
			return diags
		}

		if internalServerError, ok := err.(*cloud_policies.DeleteRuleOverrideInternalServerError); ok {
			diags.AddError(
				"Error Deleting Rule Override",
				fmt.Sprintf("Failed to delete rule override (500): %s, %+v", id, *internalServerError.Payload.Errors[0].Message),
			)
			return diags
		}

		diags.AddError(
			"Error Creating Rule Override",
			fmt.Sprintf("Failed to retrieve rule override %s: %+v", id, err),
		)

		return diags
	}

	return diags
}

func (r *CrowdstrikeCloudPostureRuleOverrideResource) updateRuleOverride(
	ctx context.Context,
	expiration string,
	overrideType string,
	ruleId string,
	crn string,
) (overrideId string, diags diag.Diagnostics) {

	params := cloud_policies.UpdateRuleOverrideParams{
		Context: ctx,
		Body: &models.CommonUpdateRuleOverrideRequest{
			Overrides: []*models.CommonSingleCreateRuleOverrideRequest{
				{
					OverrideType: &overrideType,
					RuleID:       &ruleId,
				},
			},
		},
	}

	if expiration != "" {
		convertedExpiration, diags := convertToRFC3339(expiration)
		if diags.HasError() {
			return "", diags
		}
		params.Body.Overrides[0].ExpiresAt = convertedExpiration
	}

	if crn != "" {
		params.Body.Overrides[0].Crn = &crn
	}

	resp, err := r.client.CloudPolicies.UpdateRuleOverride(&params)
	if err != nil {
		if badRequest, ok := err.(*cloud_policies.UpdateRuleOverrideBadRequest); ok {
			diags.AddError(
				"Error Updating Rule Override",
				fmt.Sprintf("Failed to update rule override (400): %s, %+v", ruleId, *badRequest.Payload.Errors[0].Message),
			)
			return "", diags
		}

		if notFound, ok := err.(*cloud_policies.UpdateRuleOverrideNotFound); ok {
			diags.AddError(
				"Error Updating Rule Override",
				fmt.Sprintf("Failed to update rule override (404): %s, %+v", ruleId, *notFound.Payload.Errors[0].Message),
			)
			return "", diags
		}

		if internalServerError, ok := err.(*cloud_policies.UpdateRuleOverrideInternalServerError); ok {
			diags.AddError(
				"Error Updating Rule Override",
				fmt.Sprintf("Failed to update rule override (500): %s, %+v", ruleId, *internalServerError.Payload.Errors[0].Message),
			)
			return "", diags
		}

		diags.AddError(
			"Error Updating Rule Override",
			fmt.Sprintf("Failed to update rule override %s: %+v", ruleId, err),
		)

		return "", diags
	}

	if resp == nil || resp.Payload == nil || len(resp.Payload.Resources) == 0 {
		diags.AddError(
			"Error Updating Rule Override",
			"Failed to update rule override: Payload is empty.",
		)
		return "", diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Updating Rule. Body Error",
			fmt.Sprintf("Failed to update rule: %s", err.Error()),
		)
		return "", diags
	}

	return payload.Resources[0], diags
}

func isTimestampExpired(timestampStr string) (bool, diag.Diagnostics) {
	var diags diag.Diagnostics

	timestamp, err := time.Parse(time.RFC3339, timestampStr)
	if err != nil {
		diags.AddError(
			"Error Parsing Timestamp",
			fmt.Sprintf("Failed to parse timestamp: %+v", err),
		)
	}

	return timestamp.Before(time.Now()), diags
}

func convertToRFC3339(timestamp string) (strfmt.DateTime, diag.Diagnostics) {
	var diags diag.Diagnostics

	layouts := []string{
		time.RFC3339,
		"0001-01-01T00:00:00.000Z",
	}

	for _, layout := range layouts {
		t, err := time.Parse(layout, timestamp)
		if err == nil {

			return strfmt.DateTime(t), nil
		}
	}

	diags.AddError(
		"Error Parsing Timestamp",
		fmt.Sprintf("Error parsing timestamp: %s", timestamp),
	)

	return strfmt.DateTime{}, diags
}
