package classification

import (
	"encoding/json"
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/klaudtrace/klaudtrace/internal/model"
)

// Rule defines a matching rule for resource classification.
type Rule struct {
	Pattern      string                 `json:"pattern"`
	ResourceType string                 `json:"resource_type,omitempty"`
	Domain       string                 `json:"domain"`
	AssetType    string                 `json:"asset_type"`
	Sensitivity  model.SensitivityLevel `json:"sensitivity"`
	Description  string                 `json:"description"`

	regex *regexp.Regexp `json:"-"`
}

// Config holds the classification rules.
type Config struct {
	Rules []Rule `json:"rules"`
}

// Classifier applies classification rules to AWS resources.
type Classifier struct {
	rules []Rule
}

// New creates a Classifier with default PayFlow fintech rules.
func New() *Classifier {
	c := &Classifier{}
	c.rules = append(c.rules, DefaultPayFlowRules...)
	c.compileRegexes()
	return c
}

// NewWithConfig creates a Classifier initialized with a custom Config.
func NewWithConfig(cfg *Config) (*Classifier, error) {
	c := &Classifier{rules: cfg.Rules}
	if err := c.compileRegexes(); err != nil {
		return nil, err
	}
	return c, nil
}

// LoadConfigFile loads classification rules from a JSON file.
func (c *Classifier) LoadConfigFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("failed to read classification config %q: %w", path, err)
	}
	var cfg Config
	if err := json.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("failed to parse classification config JSON: %w", err)
	}

	c.rules = append(cfg.Rules, c.rules...)
	return c.compileRegexes()
}

func (c *Classifier) compileRegexes() error {
	for i := range c.rules {
		r := &c.rules[i]
		if r.Pattern != "" {
			re, err := regexp.Compile("(?i)" + r.Pattern)
			if err != nil {
				return fmt.Errorf("invalid regex pattern %q: %w", r.Pattern, err)
			}
			r.regex = re
		}
	}
	return nil
}

// Classify matches a resource against configured rules and attaches classification metadata.
func (c *Classifier) Classify(res *model.ResourceRef) *model.AssetClassification {
	if res == nil {
		return nil
	}

	target := res.Name
	if res.ARN != "" {
		target = target + " " + res.ARN
	}

	for _, rule := range c.rules {
		if rule.ResourceType != "" && !strings.EqualFold(string(res.Type), rule.ResourceType) {
			continue
		}

		if rule.regex != nil && rule.regex.MatchString(target) {
			class := &model.AssetClassification{
				Domain:      rule.Domain,
				AssetType:   rule.AssetType,
				Sensitivity: rule.Sensitivity,
				Description: rule.Description,
				RuleSource:  rule.Pattern,
			}
			res.Classification = class
			return class
		}
	}

	return nil
}

// ClassifyAll classifies a slice of resources in place.
func (c *Classifier) ClassifyAll(resources []model.ResourceRef) []model.ResourceRef {
	for i := range resources {
		c.Classify(&resources[i])
	}
	return resources
}
