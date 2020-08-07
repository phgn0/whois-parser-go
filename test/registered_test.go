package main

import (
	"fmt"
	"testing"

	whoisparser "github.com/phgn0/whois-parser-go"
)

func TestRegisteredTlds(t *testing.T) {
	folderName := "./examples_registered" // generated using getWhoisExamples.go

	checkSavedWhoisResults(folderName, checkRegisteredWhois, t)
}

func checkRegisteredWhois(domain string, rawWhois string) error {
	_, err := whoisparser.Parse(rawWhois)
	if err == whoisparser.ErrDomainNotFound {
		return fmt.Errorf(".Parse() should not throw an error for the registered domain %v: err is %w", domain, err)
	}
	return nil
}
