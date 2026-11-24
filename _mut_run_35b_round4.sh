#!/bin/bash
# #774 mutants at 0b7731a9 (regalia-kms-35b, feedback round 4): green baseline, then one exact
# one-site replacement each, restored from git after every run. Only a named --- FAIL counts;
# a build failure or panic is a CRASH, not a kill.
set -u
PKG=./internal/operations/
PIN=0b7731a923a95bb8c5f9c96ef68b0d471835483f
HEAD_NOW=$(git rev-parse HEAD)
echo "== HEAD $HEAD_NOW"
[ "$HEAD_NOW" = "$PIN" ] || { echo "HEAD IS NOT THE PINNED #774 HEAD $PIN: stop"; exit 4; }
echo "== baseline"; base=$(go test -count=1 $PKG 2>&1); echo "$base" | tail -3
echo "$base" | grep -q '^ok' || { echo "BASELINE NOT GREEN: stop"; exit 2; }
m(){ name=$1 file=$2 from=$3 to=$4
  if ! python3 -I -c "import sys;p,a,b=sys.argv[1:];t=open(p).read();sys.exit(0 if t.count(a)==1 else 1)" "$file" "$from" "$to"; then echo "$name: NOT APPLIED (pattern not exactly once)"; return; fi
  python3 -I -c "import sys;p,a,b=sys.argv[1:];t=open(p).read();open(p,'w').write(t.replace(a,b))" "$file" "$from" "$to"
  out=$(go test -count=1 $PKG 2>&1); git checkout -q -- "$file"
  git diff --quiet || { echo "TREE NOT RESTORED after $name"; exit 3; }
  fails=$(printf '%s\n' "$out" | grep -E '^\s*--- FAIL: ' | sed -E 's/^\s*--- FAIL: ([^ ]+).*/\1/' | sort -u | paste -sd' ' -)
  if [ -n "$fails" ]; then echo "$name: KILLED by $fails";
  elif printf '%s\n' "$out" | grep -qE '^(panic:|# |FAIL\s+\S+ \[build failed\])'; then echo "$name: CRASH (not a kill)";
  else echo "$name: SURVIVED"; fi; }
V=internal/operations/cosmos_verify.go; C=internal/operations/coordinator.go
m M5 $V 'if r.SetByteSlice(signature[:32]) || s.SetByteSlice(signature[32:]) || r.IsZero()' 'if (r.SetByteSlice(signature[:32]) && false) || (s.SetByteSlice(signature[32:]) && false) || r.IsZero()'
m M10 $C '		if keyErr != nil {' '		if keyErr != nil && false {'
m A1 $V 'func cosmosSignerBound(algorithm, pin string, signerKey *policy.CosmosPublicKey) bool {
' 'func cosmosSignerBound(algorithm, pin string, signerKey *policy.CosmosPublicKey) bool {
	return true
'
m A2 $V 'if !ok || !signer.equal(key) {' 'if !ok || (false && !signer.equal(key)) {'
m A3 $V 'if subtle.ConstantTimeCompare([]byte("sha256:"+hex.EncodeToString(sum[:])), []byte(pin)) != 1 {' 'if false && subtle.ConstantTimeCompare([]byte("sha256:"+hex.EncodeToString(sum[:])), []byte(pin)) != 1 {'
m A4 $V '	if pin == "" && signerKey == nil {
		return errCosmosSignatureUnverified
	}' '	if pin == "" && signerKey == nil {
		return nil
	}'
m M-len $V '	if len(key.Key) != 33 || (key.Key[0] != 0x02 && key.Key[0] != 0x03) {' '	if len(key.Key) < 2 {'
m M-late $V '		if !cosmosSignerBound(route.Algorithm, route.Binding.PublicKeySHA256, parsed.SignerPublicKey) {' '		if false && !cosmosSignerBound(route.Algorithm, route.Binding.PublicKeySHA256, parsed.SignerPublicKey) {'
m M99 $V 'func verifySecp256k1(key *secp256k1.PublicKey, digest, signature []byte) bool {' 'func verifySecp256k1(key *secp256k1.PublicKey, digest, signature []byte) bool { // m99'
