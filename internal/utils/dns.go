package utils

import (
	"errors"

	"github.com/weppos/publicsuffix-go/publicsuffix"
	"github.com/asaskevich/govalidator"
)

func ExtractApex(hostname string) (string, error) {
	for hostname[len(hostname)-1] == '.' {
		hostname = hostname[:len(hostname)-1]
	}

	if !govalidator.IsDNSName(hostname) {
		return "", errors.New("invalid fqdn")
	}

	var apex, err = publicsuffix.DomainFromListWithOptions(publicsuffix.DefaultList, hostname, &publicsuffix.FindOptions{IgnorePrivate: true})
	return apex, err
}