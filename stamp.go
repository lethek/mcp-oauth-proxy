package main

import (
	"crypto/sha256"
	"encoding/hex"
	"strconv"
	"strings"
)

// stampFormat is the first element of the hashed tuple. Changing what is hashed
// is a migration that signs everyone out, so it is always deliberate.
const stampFormat = 1

// Stamp names what decides where a credential held for this target goes: the
// name, the upstream URL, the credential mode and the header names and prefixes
// a stored per-user credential was built from. A row stamped X was made for
// that destination, so a process holding a different definition will not
// honour it. Sharing a database is safe only for replicas of one deployment
// during a rolling deploy; one database still belongs to one deployment.
//
// Labels, the display name, allowed groups and static header values are left
// out on purpose: none of them changes where a stored credential is sent.
func (t Target) Stamp() string {
	// Every element is a Go-quoted string, which escapes invalid UTF-8 as \xNN
	// instead of replacing it, so two values that differ in any byte hash
	// differently. A quoted string is self-delimiting, so the space-joined
	// sequence cannot be read two ways.
	parts := []string{
		strconv.Itoa(stampFormat),
		strconv.Quote(t.Name),
		strconv.Quote(t.UpstreamMCP),
		strconv.Quote(string(t.Mode)),
		strconv.Itoa(len(t.UserFields)),
	}
	for _, f := range t.UserFields {
		parts = append(parts, strconv.Quote(f.Header), strconv.Quote(f.Prefix))
	}
	// The final element is the admin target's generation, empty for config.
	parts = append(parts, strconv.Quote(""))
	sum := sha256.Sum256([]byte(strings.Join(parts, " ")))
	return "config:" + hex.EncodeToString(sum[:])
}
