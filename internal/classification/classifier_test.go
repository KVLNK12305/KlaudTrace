package classification_test

import (
	"testing"

	"github.com/klaudtrace/klaudtrace/internal/classification"
	"github.com/klaudtrace/klaudtrace/internal/model"
)

func TestClassifier_DefaultPayFlow(t *testing.T) {
	c := classification.New()

	tests := []struct {
		name         string
		res          model.ResourceRef
		expectedType string
		expectedSens model.SensitivityLevel
	}{
		{
			name: "S3 transaction bucket",
			res: model.ResourceRef{
				Type: model.ResourceTypeS3Bucket,
				Name: "payflow-transaction-data",
				ARN:  "arn:aws:s3:::payflow-transaction-data",
			},
			expectedType: "transaction_data",
			expectedSens: model.SensitivityCritical,
		},
		{
			name: "S3 KYC document object",
			res: model.ResourceRef{
				Type: model.ResourceTypeS3Object,
				Name: "payflow-kyc-documents/user123/passport.pdf",
				ARN:  "arn:aws:s3:::payflow-kyc-documents/user123/passport.pdf",
			},
			expectedType: "kyc_data",
			expectedSens: model.SensitivityCritical,
		},
		{
			name: "KMS payment token key",
			res: model.ResourceRef{
				Type: model.ResourceTypeKMSKey,
				Name: "alias/payment-token-key",
			},
			expectedType: "payment_credentials",
			expectedSens: model.SensitivityCritical,
		},
		{
			name: "Unclassified benign resource",
			res: model.ResourceRef{
				Type: model.ResourceTypeS3Bucket,
				Name: "payflow-static-assets-frontend",
			},
			expectedType: "",
			expectedSens: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := tt.res
			class := c.Classify(&res)
			if tt.expectedType == "" {
				if class != nil {
					t.Errorf("expected no classification, got %+v", class)
				}
			} else {
				if class == nil {
					t.Fatalf("expected classification, got nil")
				}
				if class.AssetType != tt.expectedType {
					t.Errorf("expected asset type %s, got %s", tt.expectedType, class.AssetType)
				}
				if class.Sensitivity != tt.expectedSens {
					t.Errorf("expected sensitivity %s, got %s", tt.expectedSens, class.Sensitivity)
				}
			}
		})
	}
}
