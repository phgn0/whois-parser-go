package main

import (
	"fmt"
	"testing"

	whoisparser "github.com/phgn0/whois-parser-go"
)

func TestBlockedDomains(t *testing.T) {
	checkSavedWhoisResults("./examples_blocked", checkBlockedDomain, t)
}

func checkBlockedDomain(domain string, rawWhois string) error {
	_, err := whoisparser.Parse(rawWhois)
	if err == whoisparser.ErrBlockedDomain {
		return fmt.Errorf(domain)
	}
	return nil
}
