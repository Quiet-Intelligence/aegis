package adjudicator

type Decision string

const (
	DecisionAllow   Decision = "Allow"
	DecisionDeny    Decision = "Deny"
	DecisionAskUser Decision = "AskUser"
)
