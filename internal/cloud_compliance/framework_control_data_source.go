package cloudcompliance

import (
	"context"
	"fmt"

	"github.com/crowdstrike/gofalcon/falcon"
	"github.com/crowdstrike/gofalcon/falcon/client"
	"github.com/crowdstrike/gofalcon/falcon/client/cloud_policies"
	"github.com/crowdstrike/gofalcon/falcon/models"
	"github.com/crowdstrike/terraform-provider-crowdstrike/internal/utils"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

var (
	_ datasource.DataSource              = &cloudComplianceFrameworkControlDataSource{}
	_ datasource.DataSourceWithConfigure = &cloudComplianceFrameworkControlDataSource{}
)

func NewCloudComplianceFrameworkControlDataSource() datasource.DataSource {
	return &cloudComplianceFrameworkControlDataSource{}
}

type cloudComplianceFrameworkControlDataSource struct {
	client *client.CrowdStrikeAPISpecification
}

type cloudComplianceFrameworkControlDataSourceModel struct {
	Controls    []cloudComplianceFrameworkControlModel `tfsdk:"controls"`
	Name        types.String                           `tfsdk:"name"`
	Benchmark   types.String                           `tfsdk:"benchmark"`
	Requirement types.String                           `tfsdk:"requirement"`
	FQL         types.String                           `tfsdk:"fql"`
}

type cloudComplianceFrameworkControlModel struct {
	Authority   types.String `tfsdk:"authority"`
	Code        types.String `tfsdk:"code"`
	Requirement types.String `tfsdk:"requirement"`
	Benchmark   types.String `tfsdk:"benchmark"`
	Name        types.String `tfsdk:"name"`
	Section     types.String `tfsdk:"section"`
	UUID        types.String `tfsdk:"uuid"`
}

func (r *cloudComplianceFrameworkControlDataSource) Configure(
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

func (r *cloudComplianceFrameworkControlDataSource) Metadata(
	_ context.Context,
	req datasource.MetadataRequest,
	resp *datasource.MetadataResponse,
) {
	resp.TypeName = req.ProviderTypeName + "_cloud_compliance_framework_controls"
}

func (r *cloudComplianceFrameworkControlDataSource) Schema(
	_ context.Context,
	_ datasource.SchemaRequest,
	resp *datasource.SchemaResponse,
) {
	resp.Schema = schema.Schema{
		MarkdownDescription: utils.MarkdownDescription(
			"Cloud Compliance",
			"This data source retrieves all or a subset of controls within compliance benchmarks. "+
				"You can search within a single benchmark using the 'benchmark', 'name', and 'requirement' fields, "+
				"or across multiple benchmarks using an FQL filter. "+
				"When using 'name', 'benchmark', and 'requirement', the 'benchmark' field is required.",
			cloudComplianceFrameworkScopes,
		),
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Name of the control.",
			},
			"benchmark": schema.StringAttribute{
				Optional:    true,
				Description: "Name of the compliance benchmark in the framework.",
			},
			"requirement": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Version of the control.",
			},
			"fql": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Falcon Query Language (FQL) filter for advanced control searches. " +
					"FQL filter, allowed props: " +
					"*compliance_control_name* " +
					"*compliance_control_authority* " +
					"*compliance_control_type* " +
					"*compliance_control_section* " +
					"*compliance_control_requirement* " +
					"*compliance_control_benchmark_name* " +
					"*compliance_control_benchmark_version*",
			},
			"controls": schema.SetNestedAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Security framework and compliance rule information.",
				NestedObject: schema.NestedAttributeObject{
					Attributes: map[string]schema.Attribute{
						"authority": schema.StringAttribute{
							Optional:    true,
							Description: "This compliance authority for the framework",
						},
						"code": schema.StringAttribute{
							Required:    true,
							Description: "The unique compliance framework rule code.",
						},
						"requirement": schema.StringAttribute{
							Optional:    true,
							Description: "The compliance framework rule code.",
						},
						"benchmark": schema.StringAttribute{
							Optional:    true,
							Description: "The compliance benchmark within the framework.",
						},
						"name": schema.StringAttribute{
							Required:    true,
							Description: "The name of the control.",
						},
						"section": schema.StringAttribute{
							Optional:    true,
							Description: "The section within the compliance benchmark.",
						},
						"uuid": schema.StringAttribute{
							Required:    true,
							Description: "The uuid of the control.",
						},
					},
				},
			},
		},
	}
}

func (d *cloudComplianceFrameworkControlDataSource) ValidateConfig(ctx context.Context, req datasource.ValidateConfigRequest, resp *datasource.ValidateConfigResponse) {
	var config cloudComplianceFrameworkControlDataSourceModel

	// Get the configuration
	diags := req.Config.Get(ctx, &config)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	if config.Benchmark.IsNull() && config.FQL.IsNull() {
		resp.Diagnostics.AddError(
			"Invalid Configuration",
			"At least one of 'benchmark' or 'fql' must be defined",
		)
	}

}

func (r *cloudComplianceFrameworkControlDataSource) Read(
	ctx context.Context,
	req datasource.ReadRequest,
	resp *datasource.ReadResponse,
) {
	var data cloudComplianceFrameworkControlDataSourceModel
	var diags diag.Diagnostics

	resp.Diagnostics.Append(req.Config.Get(ctx, &data)...)
	if resp.Diagnostics.HasError() {
		return
	}

	data.Controls, diags = r.getControls(
		ctx,
		data.FQL.ValueString(),
		data.Name.ValueString(),
		data.Requirement.ValueString(),
		data.Benchmark.ValueString(),
	)
	if diags.HasError() {
		resp.Diagnostics.Append(diags...)
		return
	}

	// Set State
	diags = resp.State.Set(ctx, &data)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
}

func (r *cloudComplianceFrameworkControlDataSource) getControls(
	ctx context.Context,
	fql string,
	name string,
	requirement string,
	benchmark string,
) ([]cloudComplianceFrameworkControlModel, diag.Diagnostics) {
	var controls []cloudComplianceFrameworkControlModel
	var diags diag.Diagnostics
	var filter string

	if fql == "" {
		filter = fmt.Sprintf("compliance_control_benchmark_name:'%s'", benchmark)

		if name != "" {
			filter = fmt.Sprintf("%s+compliance_control_name:'%s'", filter, name)
		}
		if requirement != "" {
			filter = fmt.Sprintf("%s+compliance_control_requirement:'%s'", filter, requirement)
		}
	} else {
		filter = fql
	}

	params := cloud_policies.QueryComplianceControlsParams{
		Context: ctx,
		Filter:  &filter,
	}

	resp, err := r.client.CloudPolicies.QueryComplianceControls(&params)
	if err != nil {
		if notFound, ok := err.(*cloud_policies.QueryComplianceControlsBadRequest); ok {
			diags.AddError(
				"Error Retrieving Rules",
				fmt.Sprintf("Failed retrieve rules (400): %+v", *notFound.Payload.Errors[0].Message),
			)
			return controls, diags
		}

		if notFound, ok := err.(*cloud_policies.QueryComplianceControlsInternalServerError); ok {
			diags.AddError(
				"Error Retrieving Rule",
				fmt.Sprintf("Failed retrieve rules (500): %+v", *notFound.Payload.Errors[0].Message),
			)
			return controls, diags
		}

		diags.AddError(
			"Error Retrieving Rule",
			fmt.Sprintf("Failed retrieve rules: %+v", err),
		)

		return controls, diags
	}

	payload := resp.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Retrieving Rule",
			fmt.Sprintf("Failed to retrieve rule: %s", err.Error()),
		)
		return controls, diags
	}

	if len(payload.Resources) < 1 {
		diags.AddError(
			"Error Retrieving Rule",
			fmt.Sprintf("No rules found for filter: %s", filter),
		)
		return controls, diags
	}

	controlsInfo, diags := r.describeControls(ctx, payload.Resources)
	if diags.HasError() {
		return controls, diags
	}

	for _, control := range controlsInfo {
		controls = append(controls, cloudComplianceFrameworkControlModel{
			Authority:   types.StringValue(*control.Authority),
			Code:        types.StringValue(*control.Code),
			Requirement: types.StringValue(control.Requirement),
			Benchmark:   types.StringValue(*control.SecurityFramework[0].Name),
			Name:        types.StringValue(*control.Name),
			Section:     types.StringValue(control.SectionName),
			UUID:        types.StringValue(*control.UUID),
		})
	}

	return controls, diags
}

func (r *cloudComplianceFrameworkControlDataSource) describeControls(ctx context.Context, uuids []string) ([]*models.ApimodelsControl, diag.Diagnostics) {
	var diags diag.Diagnostics
	var controls []*models.ApimodelsControl
	params := cloud_policies.GetComplianceControlsParams{
		Context: ctx,
		Ids:     uuids,
	}

	resp, err := r.client.CloudPolicies.GetComplianceControls(&params)
	if err != nil {
		if notFound, ok := err.(*cloud_policies.GetComplianceControlsBadRequest); ok {
			diags.AddError(
				"Error Retrieving Rules",
				fmt.Sprintf("Failed retrieve rules (400): %+v", *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if notFound, ok := err.(*cloud_policies.GetComplianceControlsNotFound); ok {
			diags.AddError(
				"Error Retrieving Rules",
				fmt.Sprintf("Failed retrieve rules (404): %+v", *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		if notFound, ok := err.(*cloud_policies.GetComplianceControlsInternalServerError); ok {
			diags.AddError(
				"Error Retrieving Rules",
				fmt.Sprintf("Failed retrieve rules (500): %+v", *notFound.Payload.Errors[0].Message),
			)
			return nil, diags
		}

		diags.AddError(
			"Error Retrieving Rule",
			fmt.Sprintf("Failed retrieve rules: %+v", err),
		)

		return nil, diags
	}

	payload := resp.GetPayload()
	if err = falcon.AssertNoError(payload.Errors); err != nil {
		diags.AddError(
			"Error Retrieving Rule",
			fmt.Sprintf("Failed to retrieve rule: %s", err.Error()),
		)
		return nil, diags
	}

	controls = payload.Resources

	return controls, diags
}

// func (r *cloudComplianceFrameworkControlDataSource) getFrameworkUUID(ctx context.Context, name string) (string, diag.Diagnostics) {
// 	var diags diag.Diagnostics
// 	var frameworkUUID string

// 	filter := fmt.Sprintf("compliance_framework_name:'%s'", "AWS Well-Architected Framework (Section 2 - Security) 11.2024")

// 	paramsFramework := cloud_policies.QueryComplianceFrameworksParams{
// 		Context: ctx,
// 		Filter:  &filter,
// 	}

// 	resp, err := r.client.CloudPolicies.QueryComplianceFrameworks(&paramsFramework)
// 	if err != nil {
// 		if notFound, ok := err.(*cloud_policies.QueryComplianceFrameworksBadRequest); ok {
// 			diags.AddError(
// 				"Error Retrieving Framework UUID",
// 				fmt.Sprintf("Failed to retrieve framework UUID for (400): %+v", *notFound.Payload.Errors[0].Message),
// 			)
// 			return frameworkUUID, diags
// 		}

// 		if notFound, ok := err.(*cloud_policies.QueryComplianceFrameworksInternalServerError); ok {
// 			diags.AddError(
// 				"Error Retrieving Framework UUID",
// 				fmt.Sprintf("Failed to retrieve framework UUID for (500): %+v", *notFound.Payload.Errors[0].Message),
// 			)
// 			return frameworkUUID, diags
// 		}

// 		diags.AddError(
// 			"Error Retrieving Framework UUID",
// 			fmt.Sprintf("Failed to retrieve framework UUID for %s: %+v", name, err),
// 		)

// 		return frameworkUUID, diags
// 	}

// 	payload := resp.GetPayload()
// 	if err = falcon.AssertNoError(payload.Errors); err != nil {
// 		diags.AddError(
// 			"Error Retrieving Framework UUID",
// 			fmt.Sprintf("Failed to retrieve framework UUID for %s: %s", name, err.Error()),
// 		)
// 		return frameworkUUID, diags
// 	}

// 	if len(payload.Resources) != 1 {
// 		diags.AddError(
// 			"Unique Framework Not Found",
// 			fmt.Sprintf("Failed to retrieve framework UUID for %s. %d found", name, len(payload.Resources)),
// 		)
// 		return frameworkUUID, diags
// 	}

// 	frameworkUUID = payload.Resources[0]

// 	return frameworkUUID, diags
// }

// func (r *cloudComplianceFrameworkControlDataSource) getFrameworkControls(ctx context.Context, uuid string) (models.ComplianceFrameworkSummary, diag.Diagnostics) {
// 	var frameworkControls models.ComplianceFrameworkSummary
// 	var diags diag.Diagnostics

// 	params := cloud_security_compliance.CloudComplianceFrameworkPostureSummariesParams{
// 		Context: ctx,
// 		Ids:     []string{uuid},
// 	}

// 	resp, err := r.client.CloudSecurityCompliance.CloudComplianceFrameworkPostureSummaries(&params)
// 	if err != nil {
// 		if notFound, ok := err.(*cloud_security_compliance.CloudComplianceFrameworkPostureSummariesBadRequest); ok {
// 			diags.AddError(
// 				"Error Retrieving Framework Controls",
// 				fmt.Sprintf("Failed to retrieve framework UUID for (400): %+v", *notFound.Payload.Errors[0].Message),
// 			)
// 			return frameworkControls, diags
// 		}

// 		if notFound, ok := err.(*cloud_security_compliance.CloudComplianceFrameworkPostureSummariesForbidden); ok {
// 			diags.AddError(
// 				"Error Retrieving Framework Controls",
// 				fmt.Sprintf("Failed to retrieve framework UUID for (403): %+v", *notFound.Payload.Errors[0].Message),
// 			)
// 			return frameworkControls, diags
// 		}

// 		if notFound, ok := err.(*cloud_security_compliance.CloudComplianceFrameworkPostureSummariesRequestTimeout); ok {
// 			diags.AddError(
// 				"Error Retrieving Framework Controls",
// 				fmt.Sprintf("Failed to retrieve framework UUID for (408): %+v", *notFound.Payload.Errors[0].Message),
// 			)
// 			return frameworkControls, diags
// 		}

// 		if notFound, ok := err.(*cloud_security_compliance.CloudComplianceFrameworkPostureSummariesTooManyRequests); ok {
// 			diags.AddError(
// 				"Error Retrieving Framework Controls",
// 				fmt.Sprintf("Failed to retrieve framework UUID for (429): %+v", *notFound.Payload.Errors[0].Message),
// 			)
// 			return frameworkControls, diags
// 		}

// 		if notFound, ok := err.(*cloud_security_compliance.CloudComplianceFrameworkPostureSummariesInternalServerError); ok {
// 			diags.AddError(
// 				"Error Retrieving Framework Controls",
// 				fmt.Sprintf("Failed to retrieve framework UUID for (500): %+v", *notFound.Payload.Errors[0].Message),
// 			)
// 			return frameworkControls, diags
// 		}

// 		diags.AddError(
// 			"Error Retrieving Framework Controls",
// 			fmt.Sprintf("Failed to retrieve controls for framework %s: %+v", uuid, err),
// 		)

// 		return frameworkControls, diags
// 	}

// 	payload := resp.GetPayload()

// 	if err = falcon.AssertNoError(payload.Errors); err != nil {
// 		diags.AddError(
// 			"Error Retrieving Framework Controls",
// 			fmt.Sprintf("Failed to retrieve controls for framework %s: %s", uuid, err.Error()),
// 		)
// 		return frameworkControls, diags
// 	}

// 	if len(payload.Resources) != 1 {
// 		diags.AddError(
// 			"Error Retrieving Framework Controls",
// 			fmt.Sprintf("Failed to retrieve framework controls for %s. %d frameworks found.", uuid, len(payload.Resources)),
// 		)
// 		return frameworkControls, diags
// 	}

// 	return frameworkControls, diags
// }
