package resource

import (
	"fmt"
	"strings"

	"github.com/klaudtrace/klaudtrace/internal/model"
	"github.com/klaudtrace/klaudtrace/internal/parser"
)

// ExtractResources extracts all referenced AWS resources from a raw/normalized event.
func ExtractResources(raw *parser.RawCloudTrailEvent, norm *model.NormalizedEvent) []model.ResourceRef {
	var resources []model.ResourceRef
	seen := make(map[string]bool)

	addResource := func(res model.ResourceRef) {
		key := fmt.Sprintf("%s|%s|%s", res.Type, res.Name, res.ARN)
		if !seen[key] && (res.Name != "" || res.ARN != "") {
			seen[key] = true
			resources = append(resources, res)
		}
	}

	// 1. Check raw.Resources array if present
	if raw != nil {
		for _, r := range raw.Resources {
			res := parseRawResourceEntry(r)
			addResource(res)
		}
	}

	// 2. Extract from requestParameters and event source
	if norm != nil && norm.RequestParameters != nil {
		params := norm.RequestParameters
		service := norm.Action.Service

		switch service {
		case "s3":
			bucket, _ := params["bucketName"].(string)
			key, _ := params["key"].(string)
			if bucket != "" && key != "" {
				addResource(model.ResourceRef{
					Type:      model.ResourceTypeS3Object,
					Name:      fmt.Sprintf("%s/%s", bucket, key),
					ARN:       fmt.Sprintf("arn:aws:s3:::%s/%s", bucket, key),
					Region:    norm.AWSExecutionRegion,
					AccountID: norm.Identity.AccountID,
					Details:   map[string]string{"bucket": bucket, "key": key},
				})
			} else if bucket != "" {
				addResource(model.ResourceRef{
					Type:      model.ResourceTypeS3Bucket,
					Name:      bucket,
					ARN:       fmt.Sprintf("arn:aws:s3:::%s", bucket),
					Region:    norm.AWSExecutionRegion,
					AccountID: norm.Identity.AccountID,
				})
			}

		case "kms":
			keyID, _ := params["keyId"].(string)
			if keyID != "" {
				resType := model.ResourceTypeKMSKey
				res := model.ResourceRef{
					Type:      resType,
					Name:      keyID,
					Region:    norm.AWSExecutionRegion,
					AccountID: norm.Identity.AccountID,
				}
				if strings.HasPrefix(keyID, "arn:aws:kms:") {
					res.ARN = keyID
					res.Name = extractResourceNameFromARN(keyID)
				}
				addResource(res)
			}

		case "sqs":
			queueURL, _ := params["queueUrl"].(string)
			if queueURL != "" {
				parts := strings.Split(queueURL, "/")
				queueName := queueURL
				if len(parts) > 0 {
					queueName = parts[len(parts)-1]
				}
				addResource(model.ResourceRef{
					Type:      model.ResourceTypeSQSQueue,
					Name:      queueName,
					Region:    norm.AWSExecutionRegion,
					AccountID: norm.Identity.AccountID,
					Details:   map[string]string{"queueUrl": queueURL},
				})
			}

		case "iam":
			roleName, _ := params["roleName"].(string)
			if roleName != "" {
				addResource(model.ResourceRef{
					Type:      model.ResourceTypeIAMRole,
					Name:      roleName,
					ARN:       fmt.Sprintf("arn:aws:iam::%s:role/%s", norm.Identity.AccountID, roleName),
					AccountID: norm.Identity.AccountID,
				})
			}
			policyName, _ := params["policyName"].(string)
			if policyName != "" {
				addResource(model.ResourceRef{
					Type:      model.ResourceTypeIAMPolicy,
					Name:      policyName,
					AccountID: norm.Identity.AccountID,
				})
			}

		case "sts":
			roleArn, _ := params["roleArn"].(string)
			if roleArn != "" {
				addResource(model.ResourceRef{
					Type:      model.ResourceTypeIAMRole,
					Name:      extractResourceNameFromARN(roleArn),
					ARN:       roleArn,
					AccountID: extractAccountFromARN(roleArn),
				})
			}

		case "cloudtrail":
			trailName, _ := params["name"].(string)
			if trailName != "" {
				addResource(model.ResourceRef{
					Type:      model.ResourceTypeCloudTrail,
					Name:      trailName,
					Region:    norm.AWSExecutionRegion,
					AccountID: norm.Identity.AccountID,
				})
			}
		}
	}

	// 3. Fallback: if AssumeRole responseElements contains role info and no resources found
	if len(resources) == 0 && norm != nil && norm.Action.Normalized == "sts:AssumeRole" && norm.ResponseElements != nil {
		if assumedUser, ok := norm.ResponseElements["assumedRoleUser"].(map[string]any); ok {
			if arn, ok := assumedUser["arn"].(string); ok && arn != "" {
				addResource(model.ResourceRef{
					Type:      model.ResourceTypeIAMRole,
					Name:      extractResourceNameFromARN(arn),
					ARN:       arn,
					AccountID: extractAccountFromARN(arn),
				})
			}
		}
	}

	return resources
}

func parseRawResourceEntry(r parser.RawResource) model.ResourceRef {
	resType := mapRawResourceType(r.Type)
	name := extractResourceNameFromARN(r.ARN)
	if name == "" {
		name = r.ARN
	}
	return model.ResourceRef{
		ARN:       r.ARN,
		Type:      resType,
		Name:      name,
		AccountID: r.AccountID,
	}
}

func mapRawResourceType(t string) model.ResourceType {
	switch strings.ToLower(t) {
	case "aws::s3::bucket":
		return model.ResourceTypeS3Bucket
	case "aws::s3::object":
		return model.ResourceTypeS3Object
	case "aws::kms::key":
		return model.ResourceTypeKMSKey
	case "aws::sqs::queue":
		return model.ResourceTypeSQSQueue
	case "aws::iam::role":
		return model.ResourceTypeIAMRole
	case "aws::iam::policy":
		return model.ResourceTypeIAMPolicy
	case "aws::cloudtrail::trail":
		return model.ResourceTypeCloudTrail
	default:
		return model.ResourceTypeUnknown
	}
}

func extractResourceNameFromARN(arn string) string {
	if arn == "" {
		return ""
	}
	if strings.HasPrefix(arn, "arn:aws:s3:::") {
		return strings.TrimPrefix(arn, "arn:aws:s3:::")
	}
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	colonParts := strings.Split(arn, ":")
	if len(colonParts) > 0 {
		return colonParts[len(colonParts)-1]
	}
	return arn
}

func extractAccountFromARN(arn string) string {
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}
