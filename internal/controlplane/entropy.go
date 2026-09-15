package controlplane

import (
	"crypto/rand"
	"io"
)

// entropyReader is the package's one randomness boundary. crypto/rand.Reader is
// the production value; naming the boundary lets tests prove that entropy
// failures are returned through the package's fail-closed paths. In Go 1.26,
// crypto/rand.Read terminates the process rather than returning its documented
// error result, which would make canary's refusal branch impossible to reach.
var entropyReader io.Reader = rand.Reader
