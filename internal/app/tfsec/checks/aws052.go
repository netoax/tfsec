package checks

import (
	"fmt"

	"github.com/tfsec/tfsec/internal/app/tfsec/parser"
	"github.com/tfsec/tfsec/internal/app/tfsec/scanner"
)

const AWSRDSEncryptionNotEnabled scanner.RuleCode = "AWS052"
const AWSRDSEncryptionNotEnabledDescription scanner.RuleSummary = "RDS encryption has not been enabled at a DB Instance level."
const AWSRDSEncryptionNotEnabledExplanation = `
Encryption should be enabled for an RDS Database instances. 

When enabling encryption by setting the kms_key_id. 
`
const AWSRDSEncryptionNotEnabledBadExample = `
resource "aws_db_instance" "my-db-instance" {
	
}
`
const AWSRDSEncryptionNotEnabledGoodExample = `
resource "aws_db_instance" "my-db-instance" {
	storage_encrypted  = true
}
`

// https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html#Overview.Encryption.Availability
var unavailableEncryptionInstances = []string{
	"db.m1.small",
	"db.m1.medium",
	"db.m1.large",
	"db.m1.xlarge",
	"db.m2.xlarge",
	"db.m2.2xlarge",
	"db.m2.4xlarge",
	"db.t2.micro",
}

func isEncryptableInstance(kind string) bool {
	for _, i := range unavailableEncryptionInstances {
		if kind == i {
			return false
		}
	}

	return true
}

func init() {
	scanner.RegisterCheck(scanner.Check{
		Code: AWSRDSEncryptionNotEnabled,
		Documentation: scanner.CheckDocumentation{
			Summary:     AWSRDSEncryptionNotEnabledDescription,
			Explanation: AWSRDSEncryptionNotEnabledExplanation,
			BadExample:  AWSRDSEncryptionNotEnabledBadExample,
			GoodExample: AWSRDSEncryptionNotEnabledGoodExample,
			Links: []string{
				"https://registry.terraform.io/providers/hashicorp/aws/latest/docs/resources/db_instance",
				"https://docs.aws.amazon.com/AmazonRDS/latest/UserGuide/Overview.Encryption.html",
			},
		},
		Provider:       scanner.AWSProvider,
		RequiredTypes:  []string{"resource"},
		RequiredLabels: []string{"aws_db_instance"},
		CheckFunc: func(check *scanner.Check, block *parser.Block, _ *scanner.Context) []scanner.Result {

			instanceClass := block.GetAttribute("instance_class")
			if !isEncryptableInstance(instanceClass.Value().AsString()) {
				return nil
			}

			if block.MissingChild("storage_encrypted") {
				return []scanner.Result{
					check.NewResult(
						fmt.Sprintf("Resource '%s' has no storage encryption defined.", block.FullName()),
						block.Range(),
						scanner.SeverityError,
					),
				}
			}

			storageEncrypted := block.GetAttribute("storage_encrypted")
			if storageEncrypted.IsFalse() {
				return []scanner.Result{
					check.NewResultWithValueAnnotation(
						fmt.Sprintf("Resource '%s' has storage encrypted set to false", block.FullName()),
						storageEncrypted.Range(),
						storageEncrypted,
						scanner.SeverityError,
						),
				}
			}
			return nil
		},
	})
}
