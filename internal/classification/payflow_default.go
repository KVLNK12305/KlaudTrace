package classification

import "github.com/klaudtrace/klaudtrace/internal/model"

// DefaultPayFlowRules provides the built-in classification rules for the PayFlow demo architecture.
var DefaultPayFlowRules = []Rule{
	// Transaction Data
	{
		Pattern:     "transaction.*data",
		Domain:      "fintech",
		AssetType:   "transaction_data",
		Sensitivity: model.SensitivityCritical,
		Description: "Financial transaction records, ledger history, and settlement details",
	},
	// Account Data
	{
		Pattern:     "account.*data|account.*records",
		Domain:      "fintech",
		AssetType:   "account_data",
		Sensitivity: model.SensitivityHigh,
		Description: "Customer bank accounts, balances, and account routing info",
	},
	// KYC Data
	{
		Pattern:     "kyc.*doc|kyc.*data|kyc.*id",
		Domain:      "compliance",
		AssetType:   "kyc_data",
		Sensitivity: model.SensitivityCritical,
		Description: "Know-Your-Customer identity verification records and passports",
	},
	// KYB Data
	{
		Pattern:     "kyb.*doc|kyb.*data",
		Domain:      "compliance",
		AssetType:   "kyb_data",
		Sensitivity: model.SensitivityHigh,
		Description: "Know-Your-Business merchant verification and corporate filings",
	},
	// Payment Credentials / KMS Keys
	{
		Pattern:     "payment.*token.*key|payment.*key|payment.*credentials|card.*data",
		Domain:      "fintech",
		AssetType:   "payment_credentials",
		Sensitivity: model.SensitivityCritical,
		Description: "Cryptographic keys used to encrypt tokens, card data, and authorizations",
	},
	// Customer PII
	{
		Pattern:     "customer.*pii|customer.*records|personal.*data",
		Domain:      "fintech",
		AssetType:   "customer_pii",
		Sensitivity: model.SensitivityCritical,
		Description: "Personally identifiable customer contact and identity information",
	},
	// Audit & CloudTrail Data
	{
		Pattern:     "audit.*trail|audit.*log|cloudtrail",
		Domain:      "compliance",
		AssetType:   "audit_data",
		Sensitivity: model.SensitivityHigh,
		Description: "Immutable security audit logs and regulatory trail archives",
	},
	// SQS Payment Queue
	{
		Pattern:     "payment.*event|payment.*queue|transaction.*queue",
		Domain:      "fintech",
		AssetType:   "payment_data",
		Sensitivity: model.SensitivityHigh,
		Description: "Asynchronous payment processing queues and transaction events",
	},
	// Application Logs
	{
		Pattern:     "application.*log|app.*log",
		Domain:      "infrastructure",
		AssetType:   "application_logs",
		Sensitivity: model.SensitivityLow,
		Description: "Standard application runtime logs and debugging output",
	},
}
