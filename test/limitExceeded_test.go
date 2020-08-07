package main

import (
	"fmt"
	"testing"

	whoisparser "github.com/phgn0/whois-parser-go"
)

func TestLimitExceeded(t *testing.T) {
	checkSavedWhoisResults("./examples_registered", checkNotOutOfLimit, t)
	checkSavedWhoisResults("./examples_not-registered", checkNotOutOfLimit, t)
}

func checkNotOutOfLimit(domain string, rawWhois string) error {
	_, err := whoisparser.Parse(rawWhois)
	if err == whoisparser.ErrDomainLimitExceed {
		return fmt.Errorf(domain)
	}
	return nil
}
