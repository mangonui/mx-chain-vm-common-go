package builtInFunctions

// Gate-level DRWA metric constants.  One counter per denial code plus one for
// trie decode failures.  These are in-process counters only; the node's
// monitoring exporter must call SnapshotDRWAGateMetrics() periodically and
// publish the values to the external metrics system (Prometheus, Grafana, etc.)
const (
	drwaGateMetricDeniedPaused           = "gate_denied_token_paused"
	drwaGateMetricDeniedKYCSender        = "gate_denied_kyc_required_sender"
	drwaGateMetricDeniedAMLSender        = "gate_denied_aml_blocked_sender"
	drwaGateMetricDeniedExpiry           = "gate_denied_asset_expired"
	drwaGateMetricDeniedTransferLock     = "gate_denied_transfer_locked"
	drwaGateMetricDeniedKYCReceiver      = "gate_denied_kyc_required_receiver"
	drwaGateMetricDeniedAMLReceiver      = "gate_denied_aml_blocked_receiver"
	drwaGateMetricDeniedReceiveLock      = "gate_denied_receive_locked"
	drwaGateMetricDeniedClass            = "gate_denied_investor_class"
	drwaGateMetricDeniedJurisdiction     = "gate_denied_jurisdiction"
	drwaGateMetricDeniedAuditor          = "gate_denied_auditor_required"
	drwaGateMetricDeniedTravelRule       = "gate_denied_travel_rule_required"
	drwaGateMetricDeniedSanctions        = "gate_denied_sanctions_match"
	drwaGateMetricDeniedWindDown         = "gate_denied_wind_down_active"
	drwaGateMetricDeniedPolicyNotSynced  = "gate_denied_policy_not_synced"
	drwaGateMetricDecodeFailure          = "gate_decode_failure"
	drwaGateMetricDecodeFailureJSON      = "gate_decode_failure_json"
	drwaGateMetricDecodeFailureBinary    = "gate_decode_failure_binary"
	drwaGateMetricDecodeFailureMissing   = "gate_decode_failure_missing"
)

var drwaGate = NewDrwaCounterSet()

func recordDRWAGateMetric(metric string) {
	drwaGate.Increment(metric)
}

func resetDRWAGateMetrics() {
	drwaGate.Reset()
}

// SnapshotDRWAGateMetrics returns a point-in-time copy of all enforcement-gate
// DRWA denial and decode-failure counters.  Intended for node monitoring exporters.
func SnapshotDRWAGateMetrics() map[string]uint64 {
	return drwaGate.Snapshot()
}

// drwaDenialMetric maps a DRWA denial error code to its gate metric name.
// Returns "" for unknown codes, which callers must ignore.
func drwaDenialMetric(code error) string {
	switch code {
	case errDRWAKYCRequiredSender:
		return drwaGateMetricDeniedKYCSender
	case errDRWAKYCRequiredReceiver:
		return drwaGateMetricDeniedKYCReceiver
	case errDRWAAMLBlockedSender:
		return drwaGateMetricDeniedAMLSender
	case errDRWAAMLBlockedReceiver:
		return drwaGateMetricDeniedAMLReceiver
	case errDRWAAssetExpired:
		return drwaGateMetricDeniedExpiry
	case errDRWATokenPaused:
		return drwaGateMetricDeniedPaused
	case errDRWATransferLocked:
		return drwaGateMetricDeniedTransferLock
	case errDRWAReceiveLocked:
		return drwaGateMetricDeniedReceiveLock
	case errDRWAInvestorClass:
		return drwaGateMetricDeniedClass
	case errDRWAJurisdiction:
		return drwaGateMetricDeniedJurisdiction
	case errDRWAAuditorRequired:
		return drwaGateMetricDeniedAuditor
	case errDRWATravelRuleRequired:
		return drwaGateMetricDeniedTravelRule
	case errDRWASanctionsMatch:
		return drwaGateMetricDeniedSanctions
	case errDRWAWindDownActive:
		return drwaGateMetricDeniedWindDown
	case errDRWAPolicyNotSynced:
		return drwaGateMetricDeniedPolicyNotSynced
	default:
		return ""
	}
}
