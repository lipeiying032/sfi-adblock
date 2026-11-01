package adblock

import (
	_ "embed"
	"strings"
	"sync"
	"sync/atomic"

	C "github.com/sagernet/sing-box/constant"
	"github.com/sagernet/sing-box/option"
)

//go:embed adblock_domains.txt
var domainsText string

var enabled atomic.Bool

// SetEnabled switches the built-in ad blocking rule on or off.
func SetEnabled(value bool) {
	enabled.Store(value)
}

// Enabled reports whether the built-in ad blocking rule is enabled.
func Enabled() bool {
	return enabled.Load()
}

var (
	ruleOnce sync.Once
	rule     option.Rule
)

func buildRule() option.Rule {
	domains := make([]string, 0, 13000)
	for _, line := range strings.Split(domainsText, "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		domains = append(domains, line)
	}
	return option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RawDefaultRule: option.RawDefaultRule{
				DomainSuffix: domains,
			},
			RuleAction: option.RuleAction{
				Action: C.RuleActionTypeReject,
				RejectOptions: option.RejectActionOptions{
					Method: C.RuleActionRejectMethodDefault,
				},
			},
		},
	}
}

// Inject prepends the built-in ad blocking rules to the route configuration.
//
// The first rule sniffs the connection so that domain conditions can match
// TLS / QUIC / DNS traffic whose destination is an IP address; the second rule
// rejects every connection whose domain suffix is in the embedded list.
func Inject(options option.Options) option.Options {
	if !enabled.Load() {
		return options
	}
	ruleOnce.Do(func() {
		rule = buildRule()
	})
	if options.Route == nil {
		options.Route = &option.RouteOptions{}
	}
	rules := make([]option.Rule, 0, len(options.Route.Rules)+2)
	rules = append(rules, option.Rule{
		Type: C.RuleTypeDefault,
		DefaultOptions: option.DefaultRule{
			RuleAction: option.RuleAction{Action: C.RuleActionTypeSniff},
		},
	})
	rules = append(rules, rule)
	options.Route.Rules = append(rules, options.Route.Rules...)
	return options
}
