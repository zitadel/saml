package provider

import (
	"fmt"
	"time"
)

func checkIfRequestTimeIsStillValid(notBefore func() string, notOnOrAfter func() string, timeFormat string) func() error {
	return func() error {
		now := time.Now().UTC()
		if notBefore() != "" {
			t, err := time.Parse(timeFormat, notBefore())
			if err != nil {
				return fmt.Errorf("failed to parse NotBefore: %w", err)
			}
			if t.After(now) {
				return fmt.Errorf("before time given by NotBefore")
			}
		}

		if notOnOrAfter() != "" {
			t, err := time.Parse(timeFormat, notOnOrAfter())
			if err != nil {
				return fmt.Errorf("failed to parse NotOnOrAfter: %w", err)
			}
			if t.Equal(now) || t.Before(now) {
				return fmt.Errorf("on or after time given by NotOnOrAfter")
			}
		}
		return nil

	}
}
