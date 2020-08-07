package main

import (
	"fmt"
	"io/ioutil"
	"log"
	"path"
	"strings"
	"testing"
)

type checkFnType func(domain string, rawWhois string) error

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

		if err := checkFn(domain, string(whoisRaw)); err != nil {
			t.Errorf(err.Error())
			// return // uncomment for fail fast mode
		}
	}
}
