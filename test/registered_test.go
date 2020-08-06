package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"strings"
	"testing"

	whoisparser "github.com/phgn0/whois-parser-go"
)

type checkFnType func(domain string, rawWhois string, t *testing.T)

func checkSavedWhoisResults(folderName string, checkFn checkFnType, t *testing.T) {
	files, err := ioutil.ReadDir(folderName)
	if err != nil {
		log.Fatal(err)
	}
	for _, file := range files {
		fileName := file.Name()
		domain := fileName[:strings.Index(fileName, ".txt")]

		whoisRaw, err := ioutil.ReadFile(path.Join(folderName, fileName))
		if err != nil {
			fmt.Println(err)
			t.Errorf("Error reading saved WHOIS data for domain %v: %w", domain, err)
			continue
		}

		checkFn(domain, string(whoisRaw), t)
	}
}

func TestRegisteredTlds(t *testing.T) {
	// all tlds should have nic.* registered
	folderName := "./examples_registered" // generated using getWhoisExamples.go

	checkSavedWhoisResults(folderName, checkRegisteredWhois, t)
}

func checkRegisteredWhois(domain string, rawWhois string, t *testing.T) {
	_, err := whoisparser.Parse(rawWhois)
	if err == whoisparser.ErrDomainNotFound {
		t.Errorf(".Parse() should not throw an error for the registered domain %v: err is %w", domain, err)
	}
}
