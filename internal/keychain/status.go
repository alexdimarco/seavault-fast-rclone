package keychain

// Status describes whether the host OS keychain helper is usable.
type Status struct {
	Available bool     `json:"available"`
	Backend   string   `json:"backend"`
	Summary   string   `json:"summary"`
	Detail    string   `json:"detail,omitempty"`
	Missing   []string `json:"missing,omitempty"`
}
