package addresses

import (
	"errors"
	"regexp"
	"strings"
)

// Type to define Source and Destination address
type Addresses struct {
	Source      []byte
	Destination []byte
}

// Parse IP
func ParseIP(addr string) []byte {

	addressSlice := strings.Split(addr, ".")
	bad, _ := regexp.MatchString("[a-zA-z]", addr)

	if len(addressSlice) < 4 || bad {
		panic(errors.New("parsed incorrect address"))
	}

	buf := make([]byte, 4)

	for i := 0; i <= 3; i++ {
		buf = append(buf, []byte(addressSlice[i])...)
	}

	return buf
}
