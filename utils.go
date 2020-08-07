/*
 * Copyright 2014-2020 Li Kexian
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 *
 * Go module for domain whois information parsing
 * https://www.likexian.com/
 */

package whoisparser

import (
	"sort"
	"strings"
)

// IsNotFound returns domain is not found
func IsNotFound(data string) bool {
	ignoreSentences := []string{
		"Domain names not found in this WHOIS database are not necessarily available for registration.",
		"(i) a response from the Service indicating no match was found, does not guarantee",
	}
	for _, sentence := range ignoreSentences {
		data = strings.Replace(data, sentence, "", 1)
	}

	notExistsKeys := []string{
		"no found",
		"no match",
		"not found",
		"not match",
		"no entries found",
		"no data found",
		"no data was found",
		"this query returned 0 objects",
		"not registered",
		"not been registered",
		"object does not exist",
		"no object found",
		"object_not_found",
		"nothing found",
		"domain unknown",
		"domain name not known",
		"no such domain",
		"does not exist",
		"we do not have an entry in our database matching your query.",
		"not find matchingrecord", // .xn--55qw42g
		"is free",
		"available",
		"status: free",
		"query_status: 220 available",
		"error.",                               // .sa
		"invalid input",                        // .tr  with latin chars
		"invalid domain name",                  // .xn--90a3ac with latin chars
		"parameter value syntax error",         // .xn--90ais with latin chars
		"invalid query syntax",                 // .xn--cg4bki with latin chars
		"wrong top level domain name in query", // .xn--y9a3aq with latin chars
	}

	data = strings.ToLower(data)
	for _, v := range notExistsKeys {
		if strings.Contains(data, v) {
			// fmt.Println("found", v)
			return true
		}
	}

	return false
}

// FallbackError returns the final error after all other checks failed
func FallbackError(data string) error {
	notFoundContent := []string{
		"\r\n\r\nwhois.nic.bo solo acepta consultas con dominios .bo", // no special content for domain not found states
	}
	for _, content := range notFoundContent {
		if data == content {
			return ErrDomainNotFound
		}
	}

	return ErrDomainInvalidData
}

// IsPremiumDomain returns if the domain name is available to register at a premium price
func IsPremiumDomain(data string) bool {
	notExistsKeys := []string{
		"reserved domain name",
		"reserved by the registry",
		"platinum domain",
	}

	data = strings.ToLower(data)
	for _, v := range notExistsKeys {
		if strings.Contains(data, v) {
			return true
		}
	}

	return false
}

// IsDomainBlock returns if the domain name is blocked due to a DPML brand name block
func IsDomainBlock(data string) bool {
	notExistsKeys := []string{
		"the registration of this domain is restricted",
		"dpml block",
		"not available for registration",
		"object cannot be registered",
	}

	data = strings.ToLower(data)
	for _, v := range notExistsKeys {
		if strings.Contains(data, v) {
			return true
		}
	}

	return false
}

// IsLimitExceeded returns is query limit
func IsLimitExceeded(data string) bool {
	IsLimitExceededKeys := []string{
		"limit exceeded",
		"query rate is now high",
		"please try it again",
	}

	data = strings.ToLower(data)
	for _, v := range IsLimitExceededKeys {
		if strings.Contains(data, v) {
			return true
		}
	}
	return false
}

// IsDnsSecEnabled returns dnssec is enabled
func IsDnsSecEnabled(data string) bool {
	switch strings.ToLower(data) {
	case "yes", "active", "signed", "signeddelegation":
		return true
	default:
		return false
	}
}

// ClearName returns cleared key name
func ClearName(key string) string {
	if strings.Contains(key, "(") {
		key = strings.Split(key, "(")[0]
	}

	key = strings.Replace(key, "-", " ", -1)
	key = strings.Replace(key, "_", " ", -1)
	key = strings.Replace(key, "/", " ", -1)
	key = strings.Replace(key, "\\", " ", -1)
	key = strings.Replace(key, "'", " ", -1)
	key = strings.Replace(key, ".", " ", -1)

	key = strings.TrimPrefix(key, "Registry ")
	key = strings.TrimPrefix(key, "Sponsoring ")

	key = strings.TrimSpace(key)
	key = strings.ToLower(key)

	return key
}

// FindKeyName returns the mapper value by key
func FindKeyName(key string) string {
	key = ClearName(key)
	if v, ok := keyRule[key]; ok {
		return v
	}

	return ""
}

// FixDomainStatus returns fixed domain status
func FixDomainStatus(status []string) []string {
	for k, v := range status {
		names := strings.Split(strings.TrimSpace(v), " ")
		status[k] = strings.ToLower(names[0])
	}

	return status
}

// FixNameServers returns fixed name servers
func FixNameServers(servers []string) []string {
	for k, v := range servers {
		names := strings.Split(strings.TrimSpace(v), " ")
		servers[k] = strings.ToLower(strings.Trim(names[0], "."))
	}

	return servers
}

// Keys returns all keys of map by sort
func Keys(m map[string]string) []string {
	r := []string{}

	for k := range m {
		r = append(r, k)
	}

	sort.Strings(r)

	return r
}
