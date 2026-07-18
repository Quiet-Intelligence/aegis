package golden

import "aegis/pkg/telemetry"

type Label string

const (
	Benign    Label = "benign"
	Malicious Label = "malicious"
)

type GoldenCase struct {
	EventSequence []*telemetry.Event `json:"sequence"`
	Label         Label              `json:"label"`
	Description   string             `json:"description"`
}
