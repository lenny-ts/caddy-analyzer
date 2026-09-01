package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/lenny-ts/caddy-analyzer/pkg/audit"
	"github.com/spf13/cobra"
)

type auditNotifyFlags struct {
	auditLog, syslogAddress, webhookURL, webhookProvider string
	pagerDutyRoutingKey                                  string
	auditTimeout, auditRateLimit                         time.Duration
	auditRetries                                         int
}

func (f *auditNotifyFlags) addRest(cmd *cobra.Command) {
	cmd.Flags().StringVar(&f.syslogAddress, "audit-syslog", "", "Syslog UDP address (empty to disable, e.g. 127.0.0.1:514)")
	cmd.Flags().StringVar(&f.webhookURL, "webhook-url", "", "Webhook URL (not printed in diagnostics)")
	cmd.Flags().StringVar(&f.webhookURL, "audit-webhook", "", "Alias for --webhook-url")
	cmd.Flags().StringVar(&f.webhookProvider, "webhook-provider", "generic", "Webhook provider: generic, slack, discord, pagerduty")
	cmd.Flags().StringVar(&f.pagerDutyRoutingKey, "pagerduty-routing-key", "", "PagerDuty Events API routing key (kept out of logs)")
	cmd.Flags().DurationVar(&f.auditTimeout, "audit-timeout", 5*time.Second, "Per-sink delivery timeout")
	cmd.Flags().IntVar(&f.auditRetries, "audit-retries", 2, "Retries after the initial notification (max 5)")
	cmd.Flags().DurationVar(&f.auditRateLimit, "audit-rate-limit", 0, "Minimum time between notifications for the same IP (0 disables)")
}

func (f *auditNotifyFlags) dispatcher() (*audit.Dispatcher, error) {
	if f.auditRetries < 0 || f.auditRetries > 5 {
		return nil, fmt.Errorf("--audit-retries must be between 0 and 5")
	}
	if f.auditTimeout <= 0 {
		return nil, fmt.Errorf("--audit-timeout must be > 0")
	}
	if f.auditRateLimit < 0 {
		return nil, fmt.Errorf("--audit-rate-limit must be >= 0")
	}
	provider := strings.ToLower(strings.TrimSpace(f.webhookProvider))
	if f.webhookURL != "" {
		switch provider {
		case "generic", "slack", "discord", "pagerduty":
		default:
			return nil, fmt.Errorf("unsupported --webhook-provider %q", provider)
		}
		if provider == "pagerduty" && f.pagerDutyRoutingKey == "" {
			return nil, fmt.Errorf("--pagerduty-routing-key is required with --webhook-provider pagerduty")
		}
	}
	var sinks []audit.Sink
	var local *audit.Logger
	if f.auditLog != "" {
		l, err := audit.New(f.auditLog)
		if err != nil {
			return nil, fmt.Errorf("audit log: %w", err)
		}
		l.SetErrorHandler(func(err error) { fmt.Fprintf(os.Stderr, "audit log error: %v\n", err) })
		local = l
		sinks = append(sinks, audit.LoggerSink{Logger: l})
	}
	if f.syslogAddress != "" {
		w, err := audit.NewSyslogUDPWriter(f.syslogAddress)
		if err != nil {
			if local != nil {
				_ = local.Close()
			}
			return nil, fmt.Errorf("syslog %s: %w", f.syslogAddress, err)
		}
		sinks = append(sinks, audit.SyslogSink{Writer: w})
	}
	if f.webhookURL != "" {
		sinks = append(sinks, audit.HTTPSink{URL: f.webhookURL, Provider: provider, RoutingKey: f.pagerDutyRoutingKey})
	}
	d := audit.NewDispatcher(audit.Config{Sinks: sinks, Timeout: f.auditTimeout, Retries: f.auditRetries, PerIPRate: f.auditRateLimit,
		OnError: func(err error) { fmt.Fprintf(os.Stderr, "audit notification error: %v\n", err) }})
	return d, nil
}
