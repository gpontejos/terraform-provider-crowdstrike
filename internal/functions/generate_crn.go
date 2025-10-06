package functions

import (
	"context"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/function"
)

func NewGenerateCRN() function.Function {
	return &generateCRN{}
}

type generateCRN struct{}

func (f *generateCRN) Metadata(_ context.Context, req function.MetadataRequest, resp *function.MetadataResponse) {
	resp.Name = "generate_crn"
}

func (f *generateCRN) Definition(_ context.Context, req function.DefinitionRequest, resp *function.DefinitionResponse) {
	resp.Definition = function.Definition{
		Summary: "Formats a CrowdStrike CSPM Resource Name (CRN) based on provided parameters.",
		MarkdownDescription: "CRNs are in the format `${Provider}|${Account}|${Region}|${ResourceType}|${ResourceID}`. " +
			"A full CRN for a resource can be found in the Falcon console within Cloud Security under Assets -> Cloud Inventory.",
		Parameters: []function.Parameter{
			function.StringParameter{
				Name:                "cloud_provider",
				MarkdownDescription: "The cloud service provider for the CRN (e.g., aws, gcp, azure, vmware).",
				Validators: []function.StringParameterValidator{
					stringvalidator.OneOf("aws", "gcp", "azure"),
				},
			},
			function.StringParameter{
				Name:                "account",
				MarkdownDescription: "The unique identifier for the cloud account where the resource is located.",
			},
			function.StringParameter{
				Name: "region",
				MarkdownDescription: "The geographical region within the cloud provider's infrastructure where the resource is deployed. " +
					"Use 'global' for globally scoped resources.",
			},
			function.StringParameter{
				Name:                "resource_type",
				MarkdownDescription: "The category or classification of the cloud resource (e.g., EC2, S3, MemoryDB).",
			},
			function.StringParameter{
				Name: "resource_id",
				MarkdownDescription: "The unique identifier assigned to the specific cloud resource within its environment. " +
					"A full CRN for a resource can be found in the Falcon console within Cloud Security under Assets -> Cloud Inventory. ",
			},
		},
		Return: function.StringReturn{},
	}
}

func (f *generateCRN) Run(ctx context.Context, req function.RunRequest, resp *function.RunResponse) {
	var cloudProvider string
	var account string
	var region string
	var resourceType string
	var resourceId string
	var result string

	if resp.Error = function.ConcatFuncErrors(req.Arguments.Get(
		ctx,
		&cloudProvider,
		&account,
		&region,
		&resourceType,
		&resourceId,
	)); resp.Error != nil {
		return
	}

	if cloudProvider == "" {
		resp.Error = function.NewArgumentFuncError(0, "Invalid cloud provider. Must be one of: aws, gcp, azure")
		return
	}

	if account == "" {
		resp.Error = function.NewArgumentFuncError(1, "account cannot be empty")
		return
	}

	if region == "" {
		resp.Error = function.NewArgumentFuncError(2, "region cannot be empty")
		return
	}

	if resourceType == "" {
		resp.Error = function.NewArgumentFuncError(3, "resource_type cannot be empty")
		return
	}

	if resourceId == "" {
		resp.Error = function.NewArgumentFuncError(4, "resource_id cannot be empty")
		return
	}

	// switch cloudProvider {
	// case "aws":
	// 	if !ValidateAWSARN(resourceId) {
	// 		resp.Error = function.NewArgumentFuncError(4, "Invalid AWS ARN format for resource_id")
	// 		return
	// 	}
	// case "azure":
	// 	if !ValidateAzureResourceID(resourceId) {
	// 		resp.Error = function.NewArgumentFuncError(4, "Invalid Azure resource ID format for resource_id")
	// 		return
	// 	}
	// case "gcp":
	// 	if !ValidateGCPResourceID(resourceId) {
	// 		resp.Error = function.NewArgumentFuncError(4, "Invalid GCP resource ID format for resource_id")
	// 		return
	// 	}
	// default:
	// 	resp.Error = function.NewFuncError("Unsupported cloud provider")
	// 	return
	// }

	result = cloudProvider + "|" + account + "|" + region + "|" + resourceType + "|" + resourceId

	resp.Error = function.ConcatFuncErrors(resp.Result.Set(ctx, result))
}

// func ValidateAWSARN(arn string) bool {
// 	pattern := `^arn:aws:([a-zA-Z0-9\-]+):([a-z]{2}-[a-z]+-\d{1}|)?(:\d{12})?:(.+)$`
// 	regex := regexp.MustCompile(pattern)

// 	return regex.MatchString(arn)
// }

// func ValidateAzureResourceID(resourceID string) bool {
// 	pattern := `^/subscriptions/[0-9a-fA-F]{8}-([0-9a-fA-F]{4}-){3}[0-9a-fA-F]{12}/resourceGroups/[^/]+(/providers/[^/]+/[^/]+/[^/]+)*$`
// 	regex := regexp.MustCompile(pattern)

// 	return regex.MatchString(resourceID)
// }

// func ValidateGCPResourceID(resourceID string) bool {
// 	pattern := `^projects/[^/]+/(?:zones|regions)/[^/]+/[^/]+/[^/]+$`
// 	regex := regexp.MustCompile(pattern)

// 	return regex.MatchString(resourceID)
// }
