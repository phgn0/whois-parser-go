package main

import (
	"fmt"
	"testing"

	whoisparser "github.com/phgn0/whois-parser-go"
)

func TestNotRegisteredTlds(t *testing.T) {
	folderName := "./examples_not-registered" // generated using getWhoisExamples.go

	checkSavedWhoisResults(folderName, checkNotRegisteredWhois, t)
}

func checkNotRegisteredWhois(domain string, rawWhois string) error {
	_, err := whoisparser.Parse(rawWhois)
	if err == whoisparser.ErrDomainLimitExceed {
		return nil
	}
	if err != whoisparser.ErrDomainNotFound {
		return fmt.Errorf(".Parse() should throw an 'ErrDomainNotFound' error for the not registered domain %v: err is %w", domain, err)
	}
	return nil
}
