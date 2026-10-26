package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
)

// stampFormat is the first element of the hashed tuple. Changing what is hashed
// is a migration that signs everyone out, so it is always deliberate.
const stampFormat = 1

// Stamp names what decides where a credential held for this target goes: the
// name, the upstream URL, the credential mode and the header names and prefixes
// a stored per-user credential was built from. A row stamped X was made for
// that destination, so a process holding a different definition will not
// honour it, and processes holding different TARGETS can share a database.
//
// Labels, the display name, allowed groups and static header values are left
// out on purpose: none of them changes where a stored credential is sent.
func (t Target) Stamp() string {
	headers := make([][2]string, 0, len(t.UserFields))
	for _, f := range t.UserFields {
		headers = append(headers, [2]string{f.Header, f.Prefix})
	}
	// The final element is the admin target's generation, empty for config.
	raw, _ := json.Marshal([]any{stampFormat, t.Name, t.UpstreamMCP, string(t.Mode), headers, ""})
	sum := sha256.Sum256(raw)
	return "config:" + hex.EncodeToString(sum[:])
}
