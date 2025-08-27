package cloud_policies

import (
	"context"
	"fmt"
	"regexp"
	"strings"
	"time"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/scopes"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework-validators/int32validator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/int32default"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringdefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ resource.Resource                   = &policyRuleResource{}
	_ resource.ResourceWithConfigure      = &policyRuleResource{}
	_ resource.ResourceWithImportState    = &policyRuleResource{}
	_ resource.ResourceWithValidateConfig = &policyRuleResource{}
)

var (
	documentationSection        string         = "section"
	resourceMarkdownDescription string         = "<description>"
	requiredScopes              []scopes.Scope = []scopes.Scope{}
)

func NewPolicyRuleResource() resource.Resource {
	return &policyRuleResource{}
}

type policyRuleResource struct {
	client *client.CrowdStrikeAPISpecification
}

type policyRuleResourceModel struct {
	UUID types.String `tfsdk:"uuid"`
	// AlertInfo           types.Int32  `tfsdk:"alert_info"`
	Controls            types.Object `tfsdk:"controls"`
	Description         types.String `tfsdk:"description"`
	AutoRemediable      types.Bool   `tfsdk:"auto_remediable"`
	Domain              types.String `tfsdk:"domain"`
	Logic               types.String `tfsdk:"logic"`
	MitreTacticsId      types.String `tfsdk:"mitre_tactics_id"`
	MitreTacticsName    types.String `tfsdk:"mitre_tactics_name"`
	MitreTacticsUrl     types.String `tfsdk:"mitre_tactics_url"`
	MitreTechniquesId   types.String `tfsdk:"mitre_techniques_id"`
	MitreTechniquesName types.String `tfsdk:"mitre_techniques_name"`
	MitreTechniquesUrl  types.String `tfsdk:"mitre_techniques_url"`
	Name                types.String `tfsdk:"name"`
	ParentRuleId        types.String `tfsdk:"parent_rule_id"`
	Platform            types.String `tfsdk:"platform"`
	RemediationInfo     types.String `tfsdk:"remediation_info"`
	RemediationUrl      types.String `tfsdk:"remediation_url"`
	ResourceType        types.String `tfsdk:"resource_type"`
	Service             types.String `tfsdk:"service"`
	Severity            types.Int32  `tfsdk:"severity"`
	Subdomain           types.String `tfsdk:"subdomain"`
	LastUpdated         types.String `tfsdk:"last_updated"`
}

func (r *policyRuleResource) Configure(
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

func (r *policyRuleResource) Metadata(
	_ context.Context,
	req resource.MetadataRequest,
	resp *resource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_policy_rule"
}

func (r *policyRuleResource) Schema(
	_ context.Context,
	_ resource.SchemaRequest,
	resp *resource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(documentationSection, resourceMarkdownDescription, requiredScopes),
		Attributes: map[string]schema.Attribute{
			"uuid": schema.StringAttribute{
				Computed:    true,
				Description: "Unique identifier of the policy rule.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
						"must be a valid UUID in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			// "alert_info": schema.Int32Attribute{
			// 	Optional:    true,
			// 	Description: "1: Check if secure configuration is enabled. 2: Verify extra security features are enabled. 3: Alert on non-compliant instances.",
			// 	Validators: []validator.Int32{
			// 		int32validator.OneOf(1, 2, 3),
			// 	},
			// },
			"controls": schema.SingleNestedAttribute{
				Optional:    true,
				Description: "Security framework and compliance rule information.",
				Attributes: map[string]schema.Attribute{
					"authority": schema.StringAttribute{
						Required:    true,
						Description: "Security framework, such as CIS, NIST, or PCI.",
					},
					"code": schema.StringAttribute{
						Required:    true,
						Description: "Specific compliance rule or control number within the security framework.",
					},
				},
			},
			"description": schema.StringAttribute{
				Required:    true,
				Description: "Description of the policy rule.",
			},
			"auto_remediable": schema.BoolAttribute{
				Optional:    true,
				Description: "Autoremediation enabled for rule",
				Computed:    true,
				Default:     booldefault.StaticBool(false),
			},
			"domain": schema.StringAttribute{
				Computed:    true,
				Default:     stringdefault.StaticString("CSPM"),
				Description: "Timestamp of the last Terraform update of the resource.",
			},
			"logic": schema.StringAttribute{
				Optional:    true,
				Description: "Rego logic for the rule. If this is not defined, then parent_rule_id must be defined.",
			},
			"mitre_tactics_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "MITRE ATT&CK Tactics ID associated with the rule.",
			},
			"mitre_tactics_name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "Name of the MITRE ATT&CK Tactics associated with the rule.",
			},
			"mitre_tactics_url": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "URL to the MITRE ATT&CK Tactics associated with the rule.",
			},
			"mitre_techniques_id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "MITRE ATT&CK Techniques ID associated with the rule.",
			},
			"mitre_techniques_name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "Name of the MITRE ATT&CK Techniques associated with the rule.",
			},
			"mitre_techniques_url": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Default:     stringdefault.StaticString(""),
				Description: "URL to the MITRE ATT&CK Techniques associated with the rule.",
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Name of the policy rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"parent_rule_id": schema.StringAttribute{
				Optional:    true,
				Description: "UUID of the parent rule to inherit properties from. Required if logic is not specified.",
				Validators: []validator.String{
					stringvalidator.RegexMatches(
						regexp.MustCompile(`^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$`),
						"must be a valid UUID in the format of 7c86a274-c04b-4292-9f03-dafae42bde97",
					),
				},
			},
			"platform": schema.StringAttribute{
				Required:    true,
				Description: "Platform for the policy rule.",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"AWS",
						"Azure",
						"OCI",
						"GCP",
					),
				},
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"remediation_info": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Information about how to remediate issues detected by this rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"remediation_url": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "URL with more information about remediating issues detected by this rule.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
			"resource_type": schema.StringAttribute{
				Required:    true,
				Description: "The full resource type. Format examples: AWS: AWS::IAM::CredentialReport, Azure: Microsoft.Compute/virtualMachines, GCP: container.googleapis.com/Cluster, OCI: OCI::IAM::User",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.RequiresReplace(),
				},
			},
			"service": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "The cloud service, such as EC2 for example.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
					stringplanmodifier.RequiresReplace(),
				},
			},
			"severity": schema.Int32Attribute{
				Optional:    true,
				Computed:    true,
				Default:     int32default.StaticInt32(0),
				Description: "Severity of the rule. Valid values are 0 (critical), 1 (high), 2 (medium), 3 (informational).",
				Validators: []validator.Int32{
					int32validator.OneOf(0, 1, 2, 3),
				},
			},
			"subdomain": schema.StringAttribute{
				Required:    true,
				Description: "Subdomain for the policy rule. Valid values are 'IOM' (Indicators of Misconfiguration) or 'IAC' (Infrastructure as Code).",
				Validators: []validator.String{
					stringvalidator.OneOf(
						"IOM",
						"IAC",
					),
				},
			},
			"last_updated": schema.StringAttribute{
				Computed:    true,
				Description: "Timestamp of the last Terraform update of the resource.",
				PlanModifiers: []planmodifier.String{
					stringplanmodifier.UseStateForUnknown(),
				},
			},
		},
	}
}

func (r *policyRuleResource) Create(
	ctx context.Context,
	req resource.CreateRequest,
	resp *resource.CreateResponse,
) {
	var plan policyRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, diags := r.createCloudPolicyRule(ctx, &plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
	}

	plan.UUID = types.StringValue(*rule.UUID)
	// if rule.AlertInfo != nil {
	// 	alertInfo, err := strconv.ParseInt(*rule.AlertInfo, 10, 32)
	// 	if err != nil {
	// 		resp.Diagnostics.AddError(
	// 			"Error parsing AlertInfo",
	// 			fmt.Sprintf("Unable to parse AlertInfo value %s: %s", *rule.AlertInfo, err),
	// 		)
	// 		return
	// 	}
	// 	plan.AlertInfo = types.Int32Value(int32(alertInfo))
	// }
	plan.Description = types.StringValue(*rule.Description)
	plan.AutoRemediable = types.BoolValue(*rule.AutoRemediable)
	plan.Domain = types.StringValue(*rule.Domain)
	plan.MitreTacticsId = types.StringValue(*rule.MitreTacticsID)
	plan.MitreTacticsName = types.StringValue(*rule.MitreTacticsName)
	plan.MitreTacticsUrl = types.StringValue(*rule.MitreTacticsURL)
	plan.MitreTechniquesId = types.StringValue(*rule.MitreTechniquesID)
	plan.MitreTechniquesName = types.StringValue(*rule.MitreTechniquesName)
	plan.MitreTechniquesUrl = types.StringValue(*rule.MitreTechniquesURL)
	plan.Name = types.StringValue(*rule.Name)
	if !plan.ParentRuleId.IsNull() {
		plan.ParentRuleId = types.StringValue(rule.ParentRuleShortUUID)
	} else {
		plan.Logic = types.StringValue(rule.Logic)
	}
	plan.Platform = types.StringValue(*rule.Provider)
	plan.RemediationInfo = types.StringValue(*rule.Remediation)
	plan.RemediationUrl = types.StringValue(rule.RemediationURL)
	plan.ResourceType = types.StringValue(*rule.ResourceTypes[0].ResourceType)
	plan.Service = types.StringValue(*rule.ResourceTypes[0].Service)
	plan.Severity = types.Int32Value(int32(*rule.Severity))
	plan.Subdomain = types.StringValue(*rule.Subdomain)

	if len(rule.Controls) > 0 {
		controlsObj, _ := types.ObjectValue(
			map[string]attr.Type{
				"authority": types.StringType,
				"code":      types.StringType,
			},
			map[string]attr.Value{
				"authority": types.StringValue(*rule.Controls[0].Authority),
				"code":      types.StringValue(*rule.Controls[0].Code),
			},
		)
		plan.Controls = controlsObj
	}

	plan.LastUpdated = types.StringValue(time.Time(*rule.CreatedAt).Format(time.RFC3339))

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *policyRuleResource) Read(
	ctx context.Context,
	req resource.ReadRequest,
	resp *resource.ReadResponse,
) {
	var state policyRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, diags := r.getCloudPolicyRule(ctx, state.UUID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	if rule == nil {
		return
	}

	state.UUID = types.StringValue(*rule.UUID)
	// alertInfo, err := strconv.ParseInt(*rule.AlertInfo, 10, 32)
	// if err != nil {
	// 	resp.Diagnostics.AddError(
	// 		"Error parsing AlertInfo",
	// 		fmt.Sprintf("Unable to parse AlertInfo value %s: %s", *rule.AlertInfo, err),
	// 	)
	// 	return
	// }
	// state.AlertInfo = types.Int32Value(int32(alertInfo))
	state.Description = types.StringValue(*rule.Description)
	state.AutoRemediable = types.BoolValue(*rule.AutoRemediable)
	state.Domain = types.StringValue(*rule.Domain)
	state.MitreTacticsId = types.StringValue(*rule.MitreTacticsID)
	state.MitreTacticsName = types.StringValue(*rule.MitreTacticsName)
	state.MitreTacticsUrl = types.StringValue(*rule.MitreTacticsURL)
	state.MitreTechniquesId = types.StringValue(*rule.MitreTechniquesID)
	state.MitreTechniquesName = types.StringValue(*rule.MitreTechniquesName)
	state.MitreTechniquesUrl = types.StringValue(*rule.MitreTechniquesURL)
	state.Name = types.StringValue(*rule.Name)
	if !state.ParentRuleId.IsNull() {
		state.ParentRuleId = types.StringValue(rule.ParentRuleShortUUID)
	} else {
		state.Logic = types.StringValue(rule.Logic)
	}
	state.Platform = types.StringValue(*rule.Provider)
	state.RemediationInfo = types.StringValue(*rule.Remediation)
	state.RemediationUrl = types.StringValue(rule.RemediationURL)
	state.ResourceType = types.StringValue(*rule.ResourceTypes[0].ResourceType)
	state.Service = types.StringValue(*rule.ResourceTypes[0].Service)
	state.Severity = types.Int32Value(int32(*rule.Severity))
	state.Subdomain = types.StringValue(*rule.Subdomain)

	if len(rule.Controls) > 0 {
		controlsObj, _ := types.ObjectValue(
			map[string]attr.Type{
				"authority": types.StringType,
				"code":      types.StringType,
			},
			map[string]attr.Value{
				"authority": types.StringValue(*rule.Controls[0].Authority),
				"code":      types.StringValue(*rule.Controls[0].Code),
			},
		)
		state.Controls = controlsObj
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *policyRuleResource) Update(
	ctx context.Context,
	req resource.UpdateRequest,
	resp *resource.UpdateResponse,
) {
	var plan policyRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rule, diags := r.updateCloudPolicyRule(ctx, &plan)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	plan.UUID = types.StringValue(*rule.UUID)
	// alertInfo, err := strconv.ParseInt(*rule.AlertInfo, 10, 32)
	// if err != nil {
	// 	resp.Diagnostics.AddError(
	// 		"Error parsing AlertInfo",
	// 		fmt.Sprintf("Unable to parse AlertInfo value %s: %s", *rule.AlertInfo, err),
	// 	)
	// 	return
	// }
	// plan.AlertInfo = types.Int32Value(int32(alertInfo))
	plan.Description = types.StringValue(*rule.Description)
	plan.Logic = types.StringValue(rule.Logic)
	plan.Name = types.StringValue(*rule.Name)
	plan.Platform = types.StringValue(*rule.Provider)
	plan.RemediationInfo = types.StringValue(*rule.Remediation)
	plan.RemediationUrl = types.StringValue(rule.RemediationURL)
	plan.Severity = types.Int32Value(int32(*rule.Severity))

	if len(rule.Controls) > 0 {
		controlsObj, _ := types.ObjectValue(
			map[string]attr.Type{
				"authority": types.StringType,
				"code":      types.StringType,
			},
			map[string]attr.Value{
				"authority": types.StringValue(*rule.Controls[0].Authority),
				"code":      types.StringValue(*rule.Controls[0].Code),
			},
		)
		plan.Controls = controlsObj
	}

	plan.LastUpdated = types.StringValue(time.Now().Format(time.RFC850))

	resp.Diagnostics.Append(resp.State.Set(ctx, plan)...)
}

func (r *policyRuleResource) Delete(
	ctx context.Context,
	req resource.DeleteRequest,
	resp *resource.DeleteResponse,
) {
	var state policyRuleResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	diags := r.deleteCloudPolicyRule(ctx, state.UUID.ValueString())
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}
}

func (r *policyRuleResource) ImportState(
	ctx context.Context,
	req resource.ImportStateRequest,
	resp *resource.ImportStateResponse,
) {
	resource.ImportStatePassthroughID(ctx, path.Root("uuid"), req, resp)
}

func (r *policyRuleResource) ValidateConfig(
	ctx context.Context,
	req resource.ValidateConfigRequest,
	resp *resource.ValidateConfigResponse,
) {
	var config policyRuleResourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if config.Logic.IsNull() && config.ParentRuleId.IsNull() {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"Either 'logic' or 'parent_rule_id' must be defined",
		)
	} else if !config.Logic.IsNull() && !config.ParentRuleId.IsNull() {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"Only one of 'logic' or 'parent_rule_id' can be defined",
		)
	}
}

func (r *policyRuleResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	// Only modify during create or update, not delete
	if req.Plan.Raw.IsNull() {
		return
	}

	var plan policyRuleResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Get the mitre values from parent rule
	if !plan.ParentRuleId.IsNull() {
		parentRule, diags := r.getCloudPolicyRule(ctx, plan.ParentRuleId.ValueString())
		if diags.HasError() {
			resp.Diagnostics.Append(diags...)
		}
		plan.MitreTacticsId = types.StringValue(*parentRule.MitreTacticsID)
		plan.MitreTacticsName = types.StringValue(*parentRule.MitreTacticsName)
		plan.MitreTacticsUrl = types.StringValue(*parentRule.MitreTacticsURL)
		plan.MitreTechniquesId = types.StringValue(*parentRule.MitreTechniquesID)
		plan.MitreTechniquesName = types.StringValue(*parentRule.MitreTechniquesName)
		plan.MitreTechniquesUrl = types.StringValue(*parentRule.MitreTechniquesURL)

		// Maybe need this?
		// if plan.RemediationInfo.IsNull() {
		// 	plan.RemediationInfo = types.StringValue(*parentRule.Remediation)
		// }

		// if plan.RemediationUrl.IsNull() {
		// 	plan.RemediationUrl = types.StringValue(parentRule.RemediationURL)
		// }
	}

	resp.Plan.Set(ctx, &plan)
}

func (r *policyRuleResource) createCloudPolicyRule(ctx context.Context, plan *policyRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	body := &models.CommonCreateRuleRequest{
		Description:  plan.Description.ValueStringPointer(),
		Name:         plan.Name.ValueStringPointer(),
		Platform:     plan.Platform.ValueStringPointer(),
		Provider:     plan.Platform.ValueStringPointer(),
		ResourceType: plan.ResourceType.ValueStringPointer(),
		Domain:       plan.Domain.ValueStringPointer(),
		Subdomain:    plan.Subdomain.ValueStringPointer(),
	}

	if !plan.AutoRemediable.IsNull() {
		body.AutoRemediable = plan.AutoRemediable.ValueBoolPointer()
	}

	// if !plan.AlertInfo.IsNull() {
	// 	alertInfo := string(plan.AlertInfo.ValueInt32())
	// 	body.AlertInfo = &alertInfo
	// }

	if !plan.Controls.IsNull() {
		controlAuthority := plan.Controls.Attributes()["authority"].String()
		controlCode := plan.Controls.Attributes()["code"].String()
		body.Controls = []*models.DbmodelsControlReference{
			{
				Authority: &controlAuthority,
				Code:      &controlCode,
			},
		}
	}

	if !plan.Logic.IsNull() {
		body.Logic = plan.Logic.ValueStringPointer()
	}
	if !plan.MitreTacticsId.IsNull() {
		body.MitreTacticsID = plan.MitreTacticsId.ValueStringPointer()
	}
	if !plan.MitreTacticsName.IsNull() {
		body.MitreTacticsName = plan.MitreTacticsName.ValueStringPointer()
	}
	if !plan.MitreTacticsUrl.IsNull() {
		body.MitreTacticsURL = plan.MitreTacticsUrl.ValueStringPointer()
	}
	if !plan.MitreTechniquesId.IsNull() {
		body.MitreTechniquesID = plan.MitreTechniquesId.ValueStringPointer()
	}
	if !plan.MitreTechniquesName.IsNull() {
		body.MitreTechniquesName = plan.MitreTechniquesName.ValueStringPointer()
	}
	if !plan.MitreTechniquesUrl.IsNull() {
		body.MitreTechniquesURL = plan.MitreTechniquesUrl.ValueStringPointer()
	}
	if !plan.ParentRuleId.IsNull() {
		body.ParentRuleID = plan.ParentRuleId.ValueStringPointer()
	}
	if !plan.Severity.IsNull() {
		body.Severity = plan.Severity.ValueInt32Pointer()
	}

	params := cloud_policies.CreateRuleParams{
		Context: ctx,
		Body:    body,
	}

	resp, err := r.client.CloudPolicies.CreateRule(&params)
	if err != nil {
		diags.AddError(
			"Failed to get create rule",
			fmt.Sprintf("Failed to get create rule: %s", err),
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to create rule",
			fmt.Sprintf("Failed to create rule: %s", err.Error()),
		)
		return nil, diags
	}

	return payload.Resources[0], diags
}

func (r *policyRuleResource) getCloudPolicyRule(ctx context.Context, uuid string) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	params := cloud_policies.GetRuleParams{
		Context: ctx,
		Ids:     []string{uuid},
	}

	resp, err := r.client.CloudPolicies.GetRule(&params)
	if err != nil {

		if !strings.Contains(err.Error(), "rule resource doesn't exist") {
			diags.AddError(
				"Failed to get rule",
				fmt.Sprintf("Failed to get rule: %s", err),
			)
		}
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to get rule",
			fmt.Sprintf("Failed to get rule: %s", err.Error()),
		)
		return nil, diags
	}

	return payload.Resources[0], diags
}

func (r *policyRuleResource) updateCloudPolicyRule(ctx context.Context, plan *policyRuleResourceModel) (*models.ApimodelsRule, diag.Diagnostics) {
	var diags diag.Diagnostics

	body := &models.CommonUpdateRuleRequest{
		Description: plan.Description.ValueString(),
		Name:        plan.Name.ValueString(),
		Severity:    int64(plan.Severity.ValueInt32()),
		UUID:        plan.UUID.ValueStringPointer(),
	}

	// if !plan.AlertInfo.IsNull() {
	// 	alertInfo := string(plan.AlertInfo.ValueInt32())
	// 	body.AlertInfo = alertInfo
	// }

	if !plan.Controls.IsNull() {
		controlAuthority := plan.Controls.Attributes()["authority"].String()
		controlCode := plan.Controls.Attributes()["code"].String()
		body.Controls = []*models.ApimodelsControlReference{
			{
				Authority: &controlAuthority,
				Code:      &controlCode,
			},
		}
	}

	if !plan.Logic.IsNull() {
		body.RuleLogicList = []*models.ApimodelsRuleLogic{
			{
				Logic:           plan.Logic.String(),
				Platform:        plan.Platform.ValueStringPointer(),
				RemediationInfo: plan.RemediationInfo.ValueStringPointer(),
				RemediationURL:  plan.RemediationUrl.ValueStringPointer(),
			},
		}
	}

	if !plan.Severity.IsNull() {
		body.Severity = int64(plan.Severity.ValueInt32())
	}

	params := cloud_policies.UpdateRuleParams{
		Context: ctx,
		Body:    body,
	}

	resp, err := r.client.CloudPolicies.UpdateRule(&params)
	if err != nil {
		diags.AddError(
			"Failed to update rule",
			fmt.Sprintf("Failed to update rule: %s", err),
		)
		return nil, diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to update rule",
			fmt.Sprintf("Failed to update rule: %s", err.Error()),
		)
		return nil, diags
	}

	return payload.Resources[0], diags
}

func (r *policyRuleResource) deleteCloudPolicyRule(ctx context.Context, uuid string) diag.Diagnostics {
	var diags diag.Diagnostics

	params := cloud_policies.DeleteRuleParams{
		Context: ctx,
		Ids:     []string{uuid},
	}

	resp, err := r.client.CloudPolicies.DeleteRule(&params)
	if err != nil {
		diags.AddError(
			"Failed to delete rule",
			fmt.Sprintf("Failed to delete rule: %s", err),
		)
		return diags
	}

	payload := resp.GetPayload()

	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Failed to delete rule",
			fmt.Sprintf("Failed to delete rule: %s", err.Error()),
		)
		return diags
	}

	return diags
}
