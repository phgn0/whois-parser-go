package main

import (
	"bufio"
	"fmt"
	"io/ioutil"
	"log"
	"os"
	"path"

	"github.com/domainr/whois"
)

func main() {
	writeDomainResults("nic", "test/examples_registered")
}

func writeDomainResults(domainBase string, folderName string) {
	tlds := getTldList()
	for _, tld := range tlds {
		domain := domainBase + "." + tld
		whoisRaw, err := getWhoisString(domain)
		if err != nil {
			fmt.Println(err)
			continue
		}

		fileName := path.Join(folderName, domain+".txt")
		ioutil.WriteFile(fileName, []byte(whoisRaw), 0644)
	}
}

func getTldList() (list []string) {
	file, err := os.Open("./tlds.txt")
	if err != nil {
		log.Fatal(err)
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		list = append(list, scanner.Text())
	}

	if err := scanner.Err(); err != nil {
		log.Fatal(err)
	}

	return list
}

func getWhoisString(domain string) (string, error) {
	request, err := whois.NewRequest(domain)
	if err != nil {
		return "", fmt.Errorf("Error detecting valid DNS zone for domain %v: %w", domain, err)
	}
	whoisRaw, err := whois.DefaultClient.Fetch(request)
	if err != nil {
		return "", fmt.Errorf("Error getting WHOIS for domain %v: %w", domain, err)
	}
	return string(whoisRaw.Body), nil
}
