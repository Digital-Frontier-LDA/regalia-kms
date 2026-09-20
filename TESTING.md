# Tests that prove nothing

Every defect closed in this repository so far has been something declared in one place and honoured
in none, sitting behind a passing test suite. The tests were not absent. They ran, they were green,
and they were green for reasons unrelated to the thing they named.

This is a catalogue of the specific ways that happened here, with the real example each time. It is
not general testing advice; it is the list of mistakes this codebase has actually made.

> **Note for the open-source release.** This repository ships the Go module and its Go test suite.
> Some examples below reference the wider harness kept in the operators' private repository — the
> Python CI tiers (`tests/`, `tools/*.py`), the end-to-end scripts (`e2e/`), the deploy tooling
> (`deploy/`), and the CI workflows (`.github/`) — which are not published here. The lessons are
> general; those particular file paths are illustrative.

**What it offers is recognition, not immunity.** Reading it will not stop you writing these — the
night it was written, two of its entries caught their own author within hours, one of them added
earlier that same evening. What it buys is the twenty minutes you would otherwise
spend wondering why a falsification was quiet, or why a check you trusted said nothing. Expect that
and it delivers; expect immunity and you will conclude it failed the first time you hit §1 anyway.

## The protocol

For any test asserting a protection, **remove the protection, re-run, and read the failure text.**

The test must fail, and the message must name the defect. "It went red" is not the evidence. A test
that goes red for a setup error, an unrelated rule, or a nil value is exactly as uninformative as one
that stays green, and it is much easier to accept, because in a falsifiability pass red looks like
success.

Restore the protection and confirm green again. Both halves are the evidence.

**A check that fails for the wrong reason is more dangerous than one that passes for the wrong
reason**, because a false red gets the *check* deleted rather than the code fixed. The Staging HSM
battery has been red since 2026-08-26 for reasons unrelated to any change, and now gates nothing
(#76) — every author has learned to merge past it, which is the same as not having it. While
verifying this document I ran its identifier check from inside ``, so it looked for `kms/`
and reported all twelve identifiers missing. Had I trusted that, the honest response would have
looked like deleting the claims.

So when a check goes red, establish *why* before acting on it, in both directions.

**A falsification that produces no failure is not a result.** If you remove a protection and the test
still passes, the first question is whether the mutation created the defect at all — not whether the
test is weak. One here made an unknown approver reuse a different configured key; signature
verification rejected it for an unrelated reason, so the test passed while saying nothing about the
guard being probed. Recording that as "not caught" would have been a fabricated finding, and it reads
exactly like a real one. This is one step past "check the mutation landed": the mutation landed, and
it was the wrong mutation.

**Delete `__pycache__` around a Python mutation, or give each run a FRESH cache prefix**
(`PYTHONPYCACHEPREFIX=$(mktemp -d) python3 ...`, as a command prefix or an explicit `export` —
see below). CPython
decides a cached `.pyc` is still valid from the source's **mtime in whole seconds and its size** —
not its content. A falsification edits a file, runs, and restores, usually inside one second, and
many of the useful mutations preserve length: `isinstance(x, list)` → `isinstance(x, dict)`,
`{...}` → `[...]`, `"status"` → `"stat_s"`, `>= 2` → `>= 0`. Both fields then match and the
interpreter runs the **stale** bytecode.

Measured, on a file whose source had already been changed:

```
source says "BBBB"   interpreter behaves 'AAAA'   AGREE=False
after clearing __pycache__:  interpreter behaves 'BBBB'
```

`-B` and `PYTHONDONTWRITEBYTECODE=1` do **not** help. They stop bytecode being *written* and not
being *read*, which is the whole failure. And "fresh" is load-bearing — a prefix reused across runs
goes stale identically. Measured on a same-second, length-preserving edit:

```
default                        -> AAAA  stale
-B                             -> AAAA  stale
PYTHONDONTWRITEBYTECODE=1      -> AAAA  stale
PYTHONPYCACHEPREFIX=<reused>   -> AAAA  stale   (correct on its first run only)
PYTHONPYCACHEPREFIX=<fresh>    -> BBBB  correct
PYTHONPYCACHEPREFIX set on its own line, unexported
                               -> AAAA  stale
rm -rf __pycache__             -> BBBB  correct
```

**And the working remedy has to be applied the way a shell will honour it.** `PYTHONPYCACHEPREFIX=$(mktemp -d)`
on a line of its own sets a shell variable the Python process never sees, so the run is stale while
the reader believes it is protected — the trap this section is about, wearing the costume of the
fix for it. It must be a command prefix or an explicit `export`.

**Three remedies went into this section before anyone ran them, and each was caught by whoever
first executed it.** One that does nothing (`PYTHONDONTWRITEBYTECODE=1`), one correct only on its
first run (a reused prefix), and one correct only if the shell exports it. A harness carrying any of
them produces confident false results *while its author believes the trap is handled*, which is
worse than not knowing about the trap at all.

That progression is the strongest thing here — stronger than the original finding — because it shows
the failure **surviving two rounds of people who already knew about it**. The first was offered by
the person who found the trap and accepted by the person who reproduced it. The second went into a
paragraph correcting the first. The third went into the correction of the correction. Knowing the
mode does not stop you writing an untested claim about it; only executing the claim does.

Each surfaced the same way: somebody ran the remedy on a branch that looked finished. Everything else
about those branches said done — reproduced defect, measured evidence, green suite — and the only
unexamined thing left was the sentence telling the next person what to do, which is the sentence with
the longest reach.

**The dangerous direction is the mutation that never takes effect**, because the suite then passes
and the result is scored *"removing this guard changed nothing"* — a load-bearing guard reported as
unproven, which is the one conclusion that gets a check deleted. The reverse also happens: a restore
that leaves the mutant running makes a later, unrelated test look broken.

Every check that would normally catch a bad restore passes: `diff` says the file is correct, `grep`
finds the right line, the mutation genuinely landed on disk. **The source and the behaviour disagree
and nothing in the source tree explains it.** Go is unaffected — its build cache keys on content.

**Assert the mutation builds.** In a compiled language a broken mutation and a caught defect are
indistinguishable from the exit code. Deleting a check orphaned its import; disabling one with
`false` left a variable unused. Both produced a non-zero exit that reads exactly like the test firing
— and in both the test never ran. Read the first line of output, not the status.

Remembering to read it is not enough, because the harness is what classifies. Falsifying
`server.Serve` reported two of six mutations as caught when neither had compiled: replacing
`httpServer.Shutdown(shutdownCtx)` with `httpServer.Close()` orphaned `shutdownCtx`, and replacing
`context.WithTimeout` with `context.WithCancel` orphaned `shutdownTimeout`. The harness classified on
the word `FAIL`, which `[build failed]` contains. Make it treat `build failed` and
`declared and not used` as an **invalid** mutation — a third outcome, neither red nor green — and
write the replacement so the orphan stays alive (`_ = shutdownCtx` on the line above). Both
mutations, once they compiled, went red on the intended assertion; the harness had been reporting the
right verdict for the wrong reason.

The same harness counted a multi-line anchor with `grep -cF`, which treats each line as a separate
pattern and ORs them: a four-line anchor present exactly once was reported as matching six times, and
the run refused mutations that were in fact unique. Count occurrences of the whole block in one
string, not lines in a file.

**A guard that is not in the failure path is not a guard.** A validation step that runs beside the
thing it protects, rather than before it, protects nothing. A `git push` on the line after a
heredoc sits outside the preceding `&&` chain, so it ran after its own YAML check had already
failed and pushed a branch with no commit. The shell version of this is endemic — a `;` where `&&`
was meant, a pipe to `tail` swallowing pytest's exit code, a `grep -v` returning 1 under `pipefail`
so a successful push reads as blocked — but it is not a shell problem. An alert that cannot fire
(§10), a check that reads one file out of a merged directory (§11), and a falsification whose
mutation did not compile are the same defect: the machinery exists, looks present, and is not in the
path where it would have to act.

**The checker is code, nobody tests the checker, and its failures look exactly like results.** The
script verifying this document produced four wrong answers while the document accumulated one error:
a regex that skipped a parenthesised identifier, a path run from the wrong directory that reported
everything missing, a self-match that reported everything present, and an unstaged file it could not
distinguish from a fictional one. Every one was confident. A checker gets no review, no tests and no
falsification, while the artifact it checks gets all three — it is the least verified code in the
repository and it is the code deciding what counts as verified.

**Grep the code, not the file.** A mutation guard reported MUTATION NOT PRESENT while the mutation
was present: the grep for `O_EXCL` matched the comment explaining why `O_EXCL` is used. Same trap as
a verifier searching a corpus containing its own claims, one level in.

**Restore under a trap, not a trailing command.** The protocol mutates the tree, so an aborted run
leaves the mutation in place — and then the *next* run captures the broken state as its baseline and
reports "restored, tests pass" about a file nobody checked. The pass is indistinguishable from a real
one. This document's own falsification runs used `cp` to a scratch backup and back; one restore ran
from the wrong directory, silently copied nothing, and left the file mutated. Put the restore in a
`trap`/`defer`/`t.Cleanup` that runs on every exit path, and make it loud when it fails.

## 1. An earlier rule rejects the fixture

`TestKEKAlgorithmIsRefusedOnBindingsThatDoNotReleaseSecrets` asserted that loading a manifest
returned an error. With the new rule removed it still returned one — because the fixture was a
production object with one binding, and the redundancy rule from #27 rejected it first. The test
proved nothing in either direction and would have shipped as coverage.

This repository stacks many independent manifest rules, so any registry test is a candidate: object
identifiers, production redundancy, distinct devices, custody modes, rotation deadlines, FIDO
custody, capability support. Any of them can reject a fixture before the rule under test is reached.

**Constructing a fixture is not the same as having it.** Four cases in one night, all identical in
shape: the fixture trips an earlier check, the assertion holds for an unrelated reason, and only
removing the fix reveals it.

- umask 022 stripped the bits from a deliberately group-writable file, so a permissions test passed
  with the fix removed
- a trailing-JSON case used a key too short to reach the trailing-content check
- a substituted approver key failed signature verification before the guard being probed
- an oversized-record case used 4097 zero bytes, which fail the JSON parse whatever the size bound
  is, so raising the bound a millionfold left it green

Where a fixture must be in a particular state for the assertion to mean anything, **assert the
state**, so a fixture that cannot observe the defect fails loudly instead of passing quietly.

The fixture itself can be the earlier rule. A trailing-JSON case used `"AAAA"` as its key, which
fails a key-length check before the parser reaches the trailing content — refused for the wrong
reason, and it would have passed forever. The symptom is identical whether the *verifier* is too
strict or the *fixture* is invalid.

**The fix for both is a control.** Load the same fixture *without* the thing under test and assert it
**succeeds**, before asserting the case fails. Then assert on the error message, not on `err != nil`.

```go
// Control: the same manifest without the field must LOAD. Otherwise the assertion
// below could hold for a reason that has nothing to do with kek_algorithm.
if _, err := Load(bytes.NewBufferString(signing("")), "sitea", allHealthy{}); err != nil {
    t.Fatalf("the control manifest does not load (%v), so the case below would prove nothing", err)
}
```

## 2. The counterfactual has the wrong shape

To falsify "the binding context is derived from the route, not the caller", the obvious edit is to
use the caller's value again. But the tests had been updated to pass `nil`, so nothing opened, and
the test failed on its own happy-path assertion without ever reaching the defect.

A counterfactual must have the shape of a **partial or earlier implementation**, not a broken one.
Deriving the context from the object alone — dropping purpose and environment, which is what a
half-done fix looks like — produced the message that mattered:

```
a production envelope was released under a staging authorization: the environment
the envelope was sealed for is not the environment that was authorized
```

## 3. The test double ignores the field under test

`release-secret` could never succeed on real hardware: the only algorithm the manifest permits for it
is `opaque`, and every driver's unwrap gate accepts only RSA. Every test passed, because every
`Hardware` double in the release path ignores `route.Algorithm` entirely.

A double that accepts anything cannot fail, so a test using it asserts only that the code under test
called *something*. When the defect is in a value being passed, assert on the value the double
received:

```go
if backend.seen.Algorithm != "rsa2048" {
    t.Fatalf("the token was asked to unwrap with algorithm %q; the KEK is %q. ...", ...)
}
```

## 4. The check compares a value to itself

`envelope.validateKeyRef` compares the wrapper's backend against the envelope's KEK reference. On the
release path the wrapper was constructed as `&hardwareWrapper{backend: parsed.KEK.Backend}` — from
the envelope. The comparison could not fail, and the backend that would actually perform the unwrap
was never consulted.

A tautological check is worse than a missing one: it is documented, it is cited in review comments as
a security property, and it is invisible to any test that only supplies self-consistent input. When a
test only ever passes matched pairs, the check may be comparing one half to itself.

**The same blindness without the tautology: the check compares two genuinely different values, and
nothing ever varies one of them.** `Registry.Digest` (#221) and `epochHash` (#222) were both real
comparisons of real values, on the request path, wired correctly — and **replacing either with a
constant passed the entire kms suite.** Neither hash was the sole detector for anything, so neither
was tested as one.

The general form, and it is the question to ask of any integrity value: **reading a value is not
evidence that a wrong value would be caught.** "The code consults this digest" and "a forged digest
is refused" are different claims, and establishing the first feels like establishing the second. On
#26 I cited `keyRegistry.Digest` as the mechanism binding a fencing lease to a manifest, having
confirmed only that it was consulted; the question that found the defect was whether it
*discriminated*.

**Why it hid, which is the reusable half.** Every tamper test in the tree mangled bytes
**structurally** — truncating a record, corrupting a field, breaking the JSON. All of those are
caught by the parser, which runs first, so the suite went red for the right reason and the wrong
detector. The hash never had to work. A chain check is only exercised by an input the parser accepts
and the chain must reject.

**So the fix shape follows from the diagnosis: rewrite content with every hash field preserved.**
That is the one input a self-consistent chain cannot absorb, and the only one whose sole detector is
the hash. A test that corrupts bytes tests the parser; a test that rewrites a meaningful field and
leaves the recorded hashes intact tests the hash. `fencing/chain_binding_test.go` is the worked
example.

**How to check your own:** replace the producer of any digest, MAC, epoch or serial with a constant
— computed then ignored, so it still compiles (§18's `if false &&` pattern keeps the operands referenced) — and
run the suite. If it stays green, the comparison is decorative and the test that should have failed
does not exist. This costs a minute and it is the only evidence that separates a wired control from
a load-bearing one.

## 5. An exclusion carves out the broken case

`TestEveryAdvertisedNitrokeyCapabilityIsAcceptedByTheDriver` walks every advertised capability and
checks the driver accepts the algorithm. It excluded `release-secret` with the comment "served by
decorators in front of this provider, not by the driver". The decorator delegates; the algorithm
reaches the driver either way. The exclusion removed the one broken capability from the check written
to catch it.

Exclusions are assertions about the call graph, written in prose, that nothing verifies. When adding
one, state the mechanism rather than the conclusion — "`certs.Issuer` builds and signs the
certificate itself and never reaches the driver" can be checked by a reader; "served by decorators"
cannot.

## 6. The rule moved layers and the old guard cannot express it

The obvious repair for §5 is to delete the exclusion and let the check run. It does not work, and the
reason generalises.

The fix for that defect moved the constraint: the object still has no algorithm of its own, so
`opaque` stays correct in the capability matrix, and the algorithm that must reach the card now comes
from the manifest *binding* — which the matrix cannot see. A test walking the matrix and asserting
`wrappingAlgorithm("opaque")` would therefore fail before the fix and after it, forever. It looks
like evidence and is a permanent red.

**When a fix relocates where a rule lives, its evidence has to move too.** The matrix could still
promise something weaker and true — that a backend advertising `release-secret` has at least one
driver-accepted unwrap algorithm, so a KEK could exist at all — and the real evidence went to the
three layers the rule actually moved to: the releaser, the registry loader, and the Python validator.

Before deleting a guard because it is in the way, check whether it can still state anything true. And
before trusting one because it is green, check that what it asserts is still where the rule is.

## 7. The fixture moves from one unreachable case to another

A Python fixture used `aes-256/unwrap`, which the capability table advertised and the PKCS#11 driver
refused. The fix moved it to `opaque/release-secret` — which the table advertised and the driver also
refused. The docstring is honest about the reasoning, and the reasoning was sound; the replacement
just happened to be broken in the same way, and the check that would have caught it was the one
carrying the exclusion in §5.

When relocating a fixture off an unsupported case, verify the destination against the layer that
actually enforces it, not against the table that advertised the original.

## 8. The assertion cannot tell absence from a negative result

Review of the metrics surface (#87) found `regalia_fencing_lease_held` emitting 0 whether the lease
had been evaluated and lost, or never evaluated at all: the render discarded the flag that
distinguishes them. The gauge was correct at every instant and still lied, because an alert treating
0 as "lost the lease" pages on every restart.

The absence *was* expressed — `checked.IsZero()` suppressed the companion timestamp series — but
nothing consumed that absence. The signal was present and unread. On `main` the seam now returns
`evaluated` rather than a discarded flag, and `regalia_fencing_evaluated` carries the state
explicitly.

The testing form is the same. `if got != 0 { t.Fatal(...) }` passes when the value is a real zero and
when nothing ever set it, and those are different states. Whenever zero, empty or nil is also the
zero value of "not yet measured", assert the *distinction*: that the measured case and the unmeasured
case produce observably different output.

## 9. The test never ran

`go test` discovers only `TestXxx`, `BenchmarkXxx`, `FuzzXxx`, `ExampleXxx` and `TestMain`. A
function missing the convention compiles, is never called, and reports nothing. An `ExampleXxx` with
no `// Output:` comment is a subtler version of the same thing: it compiles, it is never executed,
and it looks exactly like a test. Check that `go test -v` lists everything you wrote — a short list
is the only symptom.

`go test ./...` compiles only the files whose build tags match the *current* build context, and the
default context excludes `piv`. The YubiKey driver is behind `//go:build piv`, so those files are
never type-checked unless you pass the tag: anything touching shared types needs
`go build -tags piv ./...` before it is believed.

**That rule has a converse, and stating only one half made it read as complete.** The case above is
tagged code the default build skips. The other case is an *untagged test that needs tagged code* —
and the command this section prescribes does not catch it. Measured on #252, where
`internal/backend/yubikey/sweep_uncovered_test.go` opened with a bare `package yubikey` and
called `NewPIVDriver`:

    go build ./...                                exit 0
    go build -tags piv ./...                      exit 0     <- the prescribed check, silent
    go vet   ./internal/backend/yubikey           exit 1     undefined: NewPIVDriver
    go test  ./internal/backend/yubikey           exit 1     [build failed]
    go test -tags piv ./internal/backend/yubikey  exit 0

`go build` does not compile test files at all, so neither build form can see a test-only
reference; and with the tag present the symbol resolves, so the tagged build has nothing to object
to. **The command that catches it is the plain `go test ./...` this section warns is insufficient.**
Run both directions: `go build -tags piv ./...` for tagged code, and `go test ./...` untagged for
tests that reach into it.

**No single command in this toolchain establishes "the tests compile".** A Go syntax error in a test
file (#253, a Python-style implicit string concatenation) is reported by one of three plausible
instruments, and the middle row is the one worth knowing:

| command | on an unparseable test file | why |
|---|---|---|
| `go build ./...` | exit 0, silent | does not compile test files at all |
| `gofmt -l ` | **stdout empty, stderr has the error, exit 2** | an unparseable file is not an unformatted one, and gofmt reports the two differently |
| `go vet ./...` | exit 1, names the file and line | compiles the test package |

`gofmt` is therefore **not** silent — but it is silent on the stream most callers read. The common
idiom `test -z "$(gofmt -l ...)"` captures stdout only, so it passes on a file gofmt could not
parse: a formatting gate blind to the worse of the two things it is looking at. **CI already gets
this right** — the KMS workflow checks the exit code first and does not suppress stderr,
with a comment saying why, because its first version had the bug:

    if ! unformatted=$(gofmt -l ); then ... exit 1; fi

Local one-liners are where it still bites, and "gofmt clean" in a report usually means the blind
idiom.

The general form: a report saying *vet clean* or *gofmt clean* is a claim about one instrument's
reach, not about the tree. Before believing a clean result, ask which of the three questions above
it actually answered.

**And what does suffice.** `go build -tags piv ./...` — the check this section used to prescribe on
its own — is blind to **both** directions, because it never compiles test files at all. Two vet
runs are what cover them, and neither alone does:

| | `go build -tags piv ./...` | `go vet ./...` | `go vet -tags piv ./...` |
|---|---|---|---|
| untagged test calling a **tagged** symbol | 0 — blind | **1** | 0 |
| **tagged** test with a broken reference | 0 — blind | 0 | **1** |

**A skip is a pass.** A test that calls `t.Skip` when a tool or fixture is missing reports success in
an environment that never had it. Where the environment is supposed to provide it — CI — the skip
should itself be an assertion: refuse to skip when `CI` is set, so a missing dependency fails the run
instead of quietly shrinking it.

**So is `-run` matching nothing.** `e2e/softhsm-pkcs11.sh` invokes its three SoftHSM tests by
exact name, `-run '^TestHTTPToCoordinatorToConcretePKCS11$'` and two others. All three exist today.
If one is renamed, `go test` prints `ok ... [no tests to run]` and **exits 0**, so the hardware
battery goes green having executed nothing. Pinning a test by name in a script couples it to that
name, and nothing else enforces the link.

**A zero exit code answers a question you did not ask.** `-run` with a pattern matching nothing exits
0 and prints `ok ... [no tests to run]`; a `FAILED` under `set +e` exits 0 and leaves the next line to
be read as the result; `gh pr edit --base main` exits 0 having changed the base and not the diff,
which still carried nine files from a squash-merged branch. Three tools, three zeroes, three claims
that were not the claim being made. Read the line that answers your question, not the status of the
command you happened to run.

**And the tree you measured may not be the tree you meant.** Both halves of this section were nearly
written wrong for the same reason, within an hour, from opposite directions:

- A grep of the working tree for the formatting check found nothing, and absence-in-my-checkout was
  read as absence-in-the-repository — the checkout predated the commit that added it. That would
  have documented a **fixed** problem as an open one.
- A reviewer resolving a filename against `git ls-files` in a checkout five commits behind reported
  it as matching **zero** files. It matches one; the branch that added it had landed since. That
  would have been a **false finding** against a correct change.

A false negative and a false positive, from the same cause: the working tree answered a question
that was asked about the repository. For any claim about what the repository does or does not
contain, read the ref — `git ls-tree -r --name-only origin/main`, `git show origin/main:<path>` —
never the checkout. This matters most for **negative** claims, because a grep that finds nothing
produces no artifact to double-check.

## 10. Referencing a thing is not covering a state

The alert rules for the metrics surface were guarded by a test asserting that every documented series
is referenced by some rule. Every series was. The rules were still blind.

Making `regalia_fencing_lease_held` *absent* before the first evaluation fixed a page-on-restart, and
in the same stroke made `RegaliaFencingEvaluationStale` unable to fire — `time()` minus a series that
does not exist matches nothing. A site whose fencing had never been evaluated was covered by no rule
while appearing to be covered by two. The series were all referenced; the *state* was not.

The suite now asks the harder question — `test_every_fencing_state_has_a_rule_that_can_actually_fire`
— and `regalia_fencing_evaluated` is emitted at 0 rather than dropped, so the state has something to
match on.

Coverage counted over the wrong noun is the general form. Every series referenced, every function
called, every line executed: none of them is every state reached.

## 11. The check read a file; the system reads a directory

Two findings on #88 had one shape. A regex pinning `pkcs11_module_path` to `/usr/lib` admitted
`/usr/lib/../../tmp/opensc-pkcs11.so`, so a check whose entire purpose was confining the module
confined nothing. And a verifier read `credentials.conf` out of a systemd drop-in *directory* —
systemd merges every `*.conf` in it, so an `override.conf` setting `User=root` satisfies every other
check in the suite.

The worst instance is not a check but a write. `writeAtomically` in the fencing lease issuer (#98,
open at the time of writing — a PR number outlives the branch it was built on) opened
`path + ".tmp"` with `O_TRUNC`. Anyone able to create that
name in advance points it at a file of their choosing, and the fencing authority — on that host, the
one process trusted to decide who may sign — truncates and rewrites it under its own privileges. The
code asked "did I write the file I named"; the system answered "I wrote wherever that name pointed."
The fix is `os.CreateTemp`, which uses `O_EXCL` and an unpredictable suffix, so a pre-created name
cannot be hit and an existing one cannot be followed. Its test plants the symlink and, with the old
code restored, the victim file comes back holding the lease — the attack demonstrated rather than
described, which is the only version worth having.

Reading one file out of a unioned directory proves something about that file and nothing about the
unit. Matching a string that contains a path proves something about the string and nothing about the
path it resolves to. Opening a name proves something about the name and nothing about the inode.

Before trusting a check, ask what the *system* consults, and confirm the check consults the same
thing. Normalise before matching; enumerate the directory rather than naming a file in it.

## 12. The name claims a universal; the code iterates a list

`TestNoListedCarrierFieldIsWrittenAndNeverRead` asserts that no *listed* carrier field is written
and never read. When the defect below was found the name carried no `Listed`, and inserting
that one word was this section's own fix — narrowing a name that claimed every carrier field to one
that claims the checked ones. The old spelling is deliberately not written out here: this document
now checks that every test name it mentions resolves, and a name kept alive only as an example of a
name that no longer exists is precisely the reference that check exists to refuse.
It walks `var carriers = map[string]string{...}` — four types, written by hand: `Draft`, `Route`,
`Binding`, `Decision`. `api.Request.IdempotencyKey` is written by the handler and read nowhere in
production, and the detector passed, because `api.Request` is not in the map. Nothing is wrong with
the check; the set it runs over is a list someone remembered to write, and a new type is invisible
by default.

This is not §5 and not §10. An exclusion is a decision with a reason attached that turns out to be
wrong — someone looked. This is **omission by default**: nobody excluded `api.Request`, nobody
declined to add it, and no reader of the test's name would guess it was absent. And the property
counted over the set is correct, unlike §10; it is the set that is short.

The general form is that **the stated scope exceeds the checked scope and nothing reconciles them.**
The same defect appears without any list at all: a comment on the SOPS socket check said the
directory being *private* is what makes the trust domain single, while the check enforced only that
it is *not writable* — a 0755 directory passes. The claim was broader than the code, in prose rather
than in a map.

Where the set can be derived, derive it. Where it genuinely cannot — "carrier" has no mechanical
definition without type information — **say so in the name and in the failure message**, so the test
claims what it checks. A check whose limits are stated is honest; one whose name overreaches is
read as coverage it does not have.

**This section was carrying an instance of its own defect, and that is the argument for checking
citations.** The fix here was applied: the test was renamed to insert `Listed`, narrowing a name
that claimed every carrier field to one that claims the listed ones. The citation in this section
was not updated, so for as long as it stood, §12 pointed at a test that no longer existed — under a
name whose whole problem was that it claimed more than the code did.

Nothing caught it because a *file* reference and a *test name* are different claims and only the
first was checked. `test_named_tests_exist.py` now checks both against this document, with the
generics that are mentioned rather than cited listed there with their reasons. A stale citation is
not a typo: in a document whose sections are arguments, the citation is where a reader goes to
check the argument, and one that resolves to nothing spends the reader's trust on the sentence
around it.

## 13. The setup did not do what it looked like

`chmod 000` on a file does not break `os.Stat`: `stat(2)` needs execute permission on the parent
directory, not read permission on the target. A test for "an unreadable file fails closed" therefore
tested nothing. To break `Stat` for a descendant, `chmod` the parent directory.

The general form: when a test asserts behaviour under a hostile condition, confirm the condition was
actually created before trusting the result.

The benign condition can be equally imaginary. `t.TempDir()` looks private, but `testing` creates
the per-test directory with `0777` and lets the umask trim it — `0755` under `umask 022`, `0775`
under the `umask 002` that user-private-group systems ship with. A checked-out file is the same:
git stores `100644`, the working tree gets `0666 &^ umask`. Every loader in this repository refuses
a group-writable file or directory, so 60-odd tests that loaded a shipped example straight from
`config/`, or handed the issuer a bare `t.TempDir()`, passed on one machine and failed on the next
without any code changing. The fixtures now `chmod 0700` the directory (`privateTempDir`) or stage
the example at `0600` (`shippedExample`), and CI runs the suite under `umask 002` so the laxer
umask is the one that has to pass.

## 14. The reason a thing is deliberately missing lives only in prose

The incident runbook (kept with the operational records, outside this repository) requires five
elements per scenario and the operator runbook requires
six. The difference is deliberate: **rollback is excluded**, because during a compromise, reversing
state is usually destroying the evidence of what happened, and a form field named *Rollback* invites
exactly that at the moment nobody has spare judgement.

The obvious way to protect that is to write it down, which was the instruction. It is not enough.
Someone reads the two contracts side by side, sees one requires a rollback and the other does not,
and draws the reasonable inference: it was forgotten. Adding it back is a one-line change that looks
like tidying, passes review, and quietly instructs an operator to undo the evidence.

**An argument that can be deleted without anything failing is a comment, and comments lose to a
plausible-looking one-line change.** So the test asserts all three: that the element is absent, that
the contract table says why, and that the paragraph explaining it is still in the document itself.

```python
self.assertNotIn("rollback", incident.elements,
                 "the incident contract now requires a rollback: during a compromise that "
                 "instructs an operator to undo the state that is also the evidence")
self.assertIn("ROLLBACK IS DELIBERATELY ABSENT", incident.why,
              "the incident contract omits rollback without saying so here")
self.assertIn('no "Rollback" here', prose,
              "the incident runbook itself does not tell a reader the omission is deliberate, "
              "so the next person to notice will add it back as a fix")
```

Three, not one, because the explanation has three homes and a reader may only visit one of them: the
test that enforces the contract, the table that records the decision, and the document an operator
actually opens at 3am.

The general form: **when a design decision is an absence, the absence needs a test, and so does its
explanation.** A presence defends itself — delete the code and something breaks. An absence defends
nothing; it looks identical to an oversight, and the person best placed to "fix" it is a careful
reader acting in good faith.

This is §5 and §12 pointed at a decision rather than at a rule. There, prose claimed something the
code did not check. Here, prose is the *only* record that a gap is intentional — which makes deleting
the prose a silent change of behaviour, one that no test would have noticed and no reviewer would
have flagged.

The same shape shows up wherever "we chose not to" is the interesting fact: a capability the
implementation refuses on purpose, a validation that is looser than it looks, a retry that is
deliberately absent. If the reason lives only in a comment, expect it to be optimised away by
someone helpful.

## 15. A comment claiming a fix forecloses the check that would find the half-fix

§14 says an absence needs a test and so does its explanation. This is the same argument for a claim
of **completion**, and it is the one that cost a real defect.

A SOPS inventory tool (kept with the operational records) documented four traps its own development had hit. A reader auditing the file
reconstructed every one of them from those docstrings — except the one whose comment said it was
handled. And they did not fail to find it: they **actively did not look**, because the comment said
the question was settled.

The trap was `git ls-tree` scoped to a subdirectory. `--full-name` had been added and the CLI stopped
truncating, so the comment was updated to say it was fixed. It was half fixed: **the flag changes how
`ls-tree` spells paths, not which paths it lists.** Handed a subdirectory the function still returned
a truncated inventory with no error — masked only because the one existing caller happened to pass a
repository root. The evidence for the fix was real; it answered a different question than the one
being asked, which is §12 and the confident-measurement failure pointed at a *fix* rather than at a
finding.

**A hazard comment recruits the next reader. A fix comment dismisses them.** That asymmetry is not
about how well either is written — it is about what each one licenses the next person to skip, and it
is why a stale fix comment survives longer than a stale hazard comment.

So: **a comment claiming something is proved should name the test that proves it, and something
should fail when that test does not exist.** `tests/test_named_tests_exist.py` is that check, over
both Go and Python. A fix comment naming a missing test is a hazard comment wearing a fix comment's
clothes, and without the check there is nothing to tell them apart.

Two consequences worth stating, because both showed up immediately:

- **Abbreviations defeat it.** `cmd/regalia-kms/main.go` said "`TestFenceRunner...` exercises it", which reads fine
  and cannot be verified. Matching is exact, so the name is now written out.
- **Where no test exists, say so in the comment.** `discover()`'s deduplication is asserted in a
  docstring and verified nowhere, so its docstring now says NOT PROVED BY ANY TEST HERE and names who
  is covering it. That is a hazard comment, which is what it should have been all along.

## 16. The guard counts the corpus that the same bug shrinks

A corpus-scanning test almost always carries a guard like `assertTrue(found)` or
`assertGreater(checked, 10)`, put there for the right reason: without it the test passes by
iterating nothing. **But the guard is worthless whenever the change you are worried about shrinks
the corpus and the findings together**, because then the ratio survives and only the scale moves.

Two instances, both found by falsification and neither visible by reading:

**The walk that skipped too much.** `test_named_tests_exist.py` scans source for `Test…` references
and test files for the tests that exist. Adding `internal` and `tests` to its `SKIP` set left every
assertion green — it had fewer references to check *and* fewer tests to check them against, so every
surviving pair still matched. `assertTrue(defined)` was guarding non-empty when the property that
mattered was *complete*. The fix is a floor on **reach**, not on count: the walk must find files
under `internal`, `cmd` and `tests`, and it names the directory it stopped finding.

**The contract that was also the corpus.** A runbook-structure test iterates the elements each
document's contract declares. Deleting `"prerequisites"` from `CUSTODY_ELEMENTS` removed the
requirement *and* the assertion that would have caught it, in one edit, with the suite green.
`assertGreater(checked, 0)` could not see it either: the count of *procedures* checked does not move
when the number of *elements* does. Pinned now with `DECLARED_ELEMENTS` — which does not stop anyone
changing a contract, it stops the change being invisible.

**And the first fix for it was the same mistake one level down.** The pin was originally a *count*,
`len(elements)`, which a deletion moves — but a **swap** does not. Trading CUSTODY's `prerequisites`
for a second entry pointing at an existing literal holds the size at 4, and with that requirement
gone, the custodian-rotation runbook lost all three of its `**Prerequisites.**` markers with nothing
red, while the identical document edit is red when the element is present. **Pin identity, not
size:** a size is a summary, and a summary is exactly what a substitution is invisible to. Names are
pinned and literals are not, because changing a literal while keeping the name is already caught —
the document then does not contain what the contract asks for.

**The question to ask of any such guard: could the change I fear reduce this number and the thing it
divides at the same time?** If yes, the guard is decoration. What works instead is a floor on
something the bug cannot move —

- **reach** rather than count: which directories, files or documents were actually visited
- **a pinned expectation** stated separately from the thing under test, so shrinking one disagrees
  with the other
- **per-source accounting**, so a corpus that stops contributing is named rather than averaged away

The same caution applies to any coverage percentage quoted as evidence in this repository. Coverage
counts lines executed, and it cannot distinguish a line executed by an assertion from a line
executed on the way to one — so a number can rise while the property gets no better guarded. What
makes a figure like 95% mean anything here is the falsification pass behind it, not the figure.
Quote the mutation that went red, not the percentage.

This is the confident-measurement failure from §14–15 pointed at a *test's own scope*. The suite is
not lying about the code; it is telling the truth about less code than you think it is reading, and
there is no red anywhere, because a test that checks fewer things still passes.

## 17. The guard you cannot make fail, because something upstream already refused

Three times in one day a guard turned out to be unreachable — the branch existed, was correct, and
could not be entered because a check further up had already rejected everything that would reach it.

| the guard | what actually refuses first |
|---|---|
| `envelope.Peek` refusing an envelope that names no KEK version | `envelope.Parse` → `validateKeyRef`, whose `keyVersionPattern` the empty string does not match |
| `registry.RouteForUnwrap` refusing an empty `kekVersion` | `validateBinding`, which requires a `kek_version` on every release binding — **two** rules (an emptiness check and a pattern check), **and two more** when the object also declares `seal-envelope`, because the seal branch repeats the pair |
| `validateReservation` refusing a date that does not round-trip | `time.Parse` with layout `2006-01-02`, strict about width and range: unpadded dates, out-of-range days, a leap day in a common year and surrounding whitespace all fail there |

**None of these is a bug, and none should be deleted.** Each is defence in depth against the
upstream check being relaxed — and the third one earned its place the same afternoon, when
loosening the layout to `2006-1-2` made the branch reachable immediately.

The problem is what they do to a test.

**You cannot falsify an unreachable guard, and the attempt produces a green that looks exactly like
a gap.** Delete the branch, run the suite, nothing goes red — the same result you would get from a
test that never checked it. Twice I recorded such a green as "not caught" and went looking for a
hole in the test before realising the hole was in my model of the code.

**And a test that appears to cover it is testing the wrong layer.** A case named *"an empty version
is refused"* passes whatever that guard does, because the input never gets that far. Left alone, the
next reader draws the reasonable conclusion — the round-trip check is what catches malformed dates,
so the `time.Parse` error check above it is redundant — and deletes the one doing the work.

So when you find one:

- **Pin the guarantee where it is enforced.** Assert that `envelope.Parse` refuses the envelope,
  that `registry.Load` refuses the manifest, that `time.Parse` refuses the date. That test can fail.
- **Say in the test that the branch is unreachable and why**, naming the upstream rule. The comment
  is the only thing standing between the guard and a future "simplification".
- **Measure it; do not reason about it.** The date case was written up as *"parses, but round-trips
  differently"* before anyone tried it. `2026-9-5` does not parse at all.
- **Check whether the upstream rule is one check or several — and on which objects.** The empty
  `kek_version` is refused by two rules for a release-only object and by four when the same object
  also seals, since the seal branch repeats the pair. A single-rule mutation therefore proves nothing
  about any of them, and the number you have to remove depends on the fixture: the one used here
  declared both operations, which is why it took four.

**A fourth shape: the branch only a race can enter.** `Serve`'s last line returns a non-sentinel
error taken from the serve goroutine *after* a graceful shutdown succeeded. Nothing upstream refuses
it; `net/http` does. `Shutdown` sets `inShutdown` before it closes the listener, so from that moment
every `Accept` failure comes back as `http.ErrServerClosed` and the arm above returns nil. The only
interleaving that reaches the last line is one where the listener had already failed before
cancellation *and* the `select` happened to choose `ctx.Done()` — a coin flip owned by the Go
scheduler.

It is tempting to loop the case fifty times and assert the listener error always survives. Do not:
the invariant is false. If the shutdown wins the race outright the goroutine never calls `Accept`, no
error is produced, and nil is the correct answer; and `net/http` has its own window between `Accept`
returning and the `shuttingDown()` check where a real error is legitimately converted to the
sentinel. A test asserting "the error is never masked" would be red on a schedule nobody controls,
which is worse than the uncovered line. `Serve` therefore sits at 95.0% with one statement
deliberately unmeasured, and this paragraph is the record of why — the number is the finding, not the
target.

**Where this section stops, because it is quotable and I misused it within the hour.** Unreachable
means *nothing can construct the input* — you cannot hand `envelope.Peek` an envelope that `Parse`
already refused, so the branch has no reachable fixture at any layer. It does **not** mean "the
current caller validates first". `Serve` took `options.ShutdownTimeout` raw while defaulting its
sibling `OperationTimeout` two lines above; I checked that `internal/config/config.go` bounds `shutdown_timeout` to
1s–2m, concluded the missing guard could not be made to fail, and cited this section for not writing
the test. `Serve` is exported and `Options{ShutdownTimeout: 0}` is a value any caller in the module
can build — #189 wrote that test and it goes red without the guard, on both zero and negative.

The check that separates the two takes one minute: **construct the input in a test.** If you can, the
guard is reachable and §17 does not apply, whatever the production caller does. Reaching for this
section before trying is how it becomes a licence rather than a finding — the failure mode it exists
to prevent, pointed the other way.

Zero was also the worse direction to be wrong in. It does not mean "shut down now": it builds an
already-expired context, so `Shutdown` grants no grace, returns `DeadlineExceeded`, and the error
arm calls `Close()`. Here an in-flight request is a signing operation against hardware, so the caller
sees a failure for an operation that ran, against a key that was used.

The reason this belongs beside §16 is that both are ways a suite reports more assurance than it has.
§16's guard counts a corpus the bug shrinks with it. This one is a check that cannot fail, sitting
in a file full of checks that can — and from the outside, on a green run, the two are identical.

## 18. A negative case needs a known-good case in the same test

A negative case ("`loadManifest` refuses a production object with one binding") and a known-good
control ("`loadManifest` accepts the same object with two bindings") must be **two halves of one
test**, and the negative case must differ from the control in exactly one respect. Without the
control, every refusal is equally consistent with a validator that refuses *everything* — and
that indistinguishability is what lets an error-path assertion that asserts only "the case was
refused" stay green while the validator, the fixture, or the named guard all changed.

Eight instances, all of the same defect, all caught by falsification rather than reading:

- a content-type check asserting the **label** (`application/pkix`) over placeholder bytes
  (`"public"`) — proved the type was reported, not that the bytes were a PKIX key
- a wrap-format check with the format guard **deleted** — passed because the fixture's fake
  public key made the wrap fail inside `keywrap` before the format was ever checked
- a journal-absence check that treated *any* `Stat` error as "absent" — a permission failure
  satisfied it without the file being checked at all
- a "version no binding holds" check denied by the **duplicate-binding** guard rather than by
  the version filter it named
- a relative-path case using a path that does not exist — `unix.Open` refused it before `IsAbs`
  could run. Switched to a real file under `t.Chdir`, which only exists in the package directory,
  so `go test -c` run elsewhere restored the same hole. Eventually `t.Chdir` plus a fixture the
  test itself wrote
- a directory-is-not-a-file case where `unix.Open` failed before the `S_IFREG` check ran
- a separator-collision pair that did not collide — I kept a hyphen on one side, so
  `"cosmos"+"hotwallet"` and `"cosmosh"+"otwallet"` were never the same string, and **both**
  separator mutations passed
- a `Stat`-returned-an-error assertion that a permission failure satisfies as readily as absence

Each of these passed as soon as the test said `err != nil`, "the file is absent," "the wrap is
invalid," "the separator collides" — and each fell over when the validator was deleted because
the fixture was already wrong in a way the test did not bound. **The control is what bounds the
fixture.** Without it, the test is a single observation, not a comparison, and a single observation
cannot tell you which difference produced the outcome.

**Build the known-good before the negative case, in the same test, so the difference is one
thing.** A helper that exercises "the same input without the bad thing must succeed" — and asserts
that it does, with a message saying so — is the cheap version:

```go
// Control: the same manifest without the field must LOAD. Otherwise the assertion
// below could hold for a reason that has nothing to do with kek_algorithm.
```

If the control passes when the field is present and the negative case passes when it is absent,
then the difference you isolated is what produced the refusal. If either half fails, the test
fails loudly with a message that names which half — not "the test fails," not "loadManifest
returned an error."

The error-path refinement matters here too. The control proves the validator can succeed; the
refusal proves the guard fired for the named reason. Both halves are required — and the message
assertion in the negative half is what names the guard:

```go
if !strings.Contains(err.Error(), test.wants) {
    t.Fatalf("openAudit() error = %q, want it to mention %q — a refusal for a different reason would leave this one unproven",
        err, test.wants)
}
```

Three of five mutations in `TestTheAuditSinkRefusesEveryWayItCouldShipUnauthenticated` (#155)
worked exactly this way: removing the mTLS-required check still errored in keypair load, ignoring
the keypair error still errored in client construction, ignoring the trust-roots read error
still errored on the empty pool. The message assertion is what catches these — without it, the
case is satisfied by every error in the chain; with it, the test pins which guard produced the
verdict.

The falsification for both halves is the same one and both have to fail. Delete the named
guard, re-run, read the failure: which message came back, what bytes came back, which status
fired. If the negative case still passes on the wrong reason, the assertion is doing nothing
the suite can see. If the control fails when it should pass, the test never reached the test.

**Assert that the mutation landed.** Twice an anchor matched two lines, so nothing was mutated
and the harness printed GREEN for an unmutated run. A run that prints GREEN and reports "guard
deleted" must have deleted exactly one thing — the test that proves it is the same test that
would have caught the wrong reason. Read the first line of the diff, not the status.

A mutation can also land and report success by coin flip, which is the same defect from the
opposite direction: not "the test is green" but "the test was green by luck this time, will be
red next time, and the run that just printed GREEN tells you nothing about the guard." The shape
that produces this is iterating a map — Go randomises map iteration, so a fixture with two
objects catches a sort-removal mutation about half the time. The falsification reads as flaky,
the run gets re-run, the second run is green, the guard is declared caught. **It was not caught —
it was caught on the runs where the runtime cooperated, and failed silently on the others.**
The fix is to size the fixture so the iteration order is irrelevant: four objects makes a
sort-removal mutation 1 in 24 of *not* finding the failure, and a run of eight catches 8/8 instead
of "sometimes catches, sometimes doesn't." A falsification that reports success intermittently
is not a falsification; the bar is "every run passes the new assertion AND every run detects the
deleted guard." If either side is intermittent, the fixture is wrong, not the test.

**§17 is where this section's advice runs out and a different one takes over.** When the guard
you named is unreachable, asserting the message and asserting the control do not save you — the
case still passes, the message still matches, the control still loads, and the guard you named
is not the one that produced any of it. Only counting the upstream rules (the §17 question)
tells you whether the assertion under test can ever fire, which is the floor under both halves
of this section.

## 19. The mutation went red, and a different guard fired

§18 asks whether a refusal distinguishes the guard from a validator that refuses everything. This
section asks the question one step earlier: **when the mutation goes red, which guard produced the
red?** A fixture that contains more than one thing capable of refusing answers a mutation with a
failure that may have nothing to do with the change.

A green that should be red is obviously suspect, so it gets investigated. A **red that is red for
the wrong reason looks like success**, and nothing prompts a second look. It certifies a guard that
was never executed, and it does so with a passing falsification recorded in the commit message.

Four instances in one day, all in security-relevant code, none found by reading:

- A forged-payload probe for a new **absence check** targeted the policy journal, where the
  pre-existing *sidecar amputation rule* refused it first. Re-aimed at the version file, where the
  absence check is the only rule that can fire.
- A forged-**sidecar** probe left the fixture's real `.shipped` mark in place, so the amputation
  refusal fired from the other sidecar. The commit already claimed the mutation was red; running it
  showed `EXIT=0` once the shipped mark was cleared, and the commit was amended rather than the
  claim quietly dropped.
- A **digest-check** mutation stayed green because the chain verifier rejected the tampered byte
  first. The digest was never the sole detector for anything — see §4, and the constant-hash case in
  `TestTheEpochChainBindsTheRecordContent`.
- A **basename-collision** test sat after the marks rule, so the marks refusal fired in the
  collision's place. Ordering the collision check first is also correct on its own terms: a
  conflatable configuration invalidates every downstream verdict.

**Name the detector before believing the red.** Grep the output for the *specific* message the guard
under test emits, not for `--- FAIL`. Where a fixture legitimately carries several guards, assert
the message rather than the exit code. Where it does not have to, remove the other refusers: strip
the sibling sidecar, pick the field with no second rule attached, and do not hand a parser
structurally invalid content when the thing under test runs after parsing.

The same asymmetry applies to review, not only to tests. Reasoning a finding away produces no
artifact and leaves no failing state, so a dismissal is never checked the way a fix is. On the same
day, a reviewer's claim that normalising a zero-byte file to *absent* bypassed a check was nearly
retired with "a truncated sidecar is indistinguishable from a deleted one, so an attacker gains
nothing" — true, and about a different question. Built as two fixtures, the same state gave
`ACCEPTED` when normalised and two distinct refusals when carried as present. **Dismissing a finding
needs the fixture that raising one needs.**

## 20. Every check in this file is advisory, and a person is the gate

Everything above argues that a test must be able to fail, must fail alone, and must be the sole
detector for the thing it claims. All of it buys **nothing at the moment of merge**, because nothing
in this repository stops a red branch from reaching `main`.

Measured on 2026-09-06, not inferred:

- `GET /repos/.../branches/main/protection` → **404, branch not protected**.
- One ruleset exists, `Required Review Gates`. Its rules are `pull_request` and
  `copilot_code_review` **only**: squash-only, thread resolution required, zero approving reviews.
- There is **no `required_status_checks` rule**, at repository or organization level.
- On a pull request parked at a deliberately-red commit: `mergeStateStatus=UNSTABLE`,
  **`mergeable=MERGEABLE`**, `custody-manifest:FAILURE`.

So with that configuration in place, the only thing `BLOCKED` can mean here is *an unresolved
review thread* — no other rule is present that could produce it. A pull request whose `kms` job is
failing is mergeable the moment its threads are resolved. That follows from the measurement above
and holds exactly as long as it does; it is not a claim about the repository's whole history.

**The discipline that has been standing in for the gate: merge only when `mergeStateStatus` reads
`CLEAN`.** It is one command, and it is the whole rule:

    gh pr view <N> --json mergeStateStatus --jq .mergeStateStatus

`CLEAN` is mergeable **and** passing commit status. `UNSTABLE` is mergeable with a check that is
pending or failing — both directions measured: pending on #225 and #226, failing on #228. `BLOCKED`
is a thread. Merging on `UNSTABLE` is the failure mode, and it looks like progress, because the
merge succeeds.

Nothing checks the four measurements above, and that is deliberate. A test asserting "this
repository still has no required status checks" is a guard **whose success condition is the defect
persisting**: it goes red the day somebody fixes the thing, so the only way to keep it green is to
never fix it. That is worse than untested — it is a mechanism that mildly discourages the repair.
The same shape applies to any check written against a known gap rather than against a rule, which is
the reason to notice it here rather than only in this instance. So the measurements are dated
instead, and re-taken with these commands:

    gh api repos/regalia-kms/regalia/branches/main/protection
    for id in $(gh api repos/regalia-kms/regalia/rulesets --jq '.[].id'); do
      gh api "repos/regalia-kms/regalia/rulesets/$id" \
        --jq '{name, enforcement, rules: [.rules[].type]}'
    done

The loop is not defensive tidiness. There is **one** ruleset today, and the change this section
exists to anticipate — somebody adding `required_status_checks` — is the most likely way a second
one appears; a command that captured `.[].id` into a single variable would break at exactly the
moment a reader runs it to find out whether the gap is closed. Selecting the known ruleset by name
has the same defect in the other direction: it would report the old ruleset's rules and never
mention the new one.

Each iteration has to print the rule TYPES, because that is the measurement. A listing of names
and targets cannot tell a reader whether `required_status_checks` is among the rules of any of
them, so citing it here would be an instrument that cannot observe the thing it is cited for — the
defect this document opens with, in the section describing how to check this one. Against the
configuration above it prints one line:

    {"enforcement":"active","name":"Required Review Gates","rules":["pull_request","copilot_code_review"]}

**A dated measurement is only as good as the command that re-takes it, and this section got that
wrong twice before it merged.** The first command printed ruleset names and targets, which cannot
say whether `required_status_checks` is among the rules — a citation to a measurement, by a command
that does not take that measurement. The second broke on a second ruleset, in the exact scenario
this section anticipates. Both were caught in review, neither by anything mechanical, because a
command inside a document is not executed by the suite.

So when the honest answer to "why is there no test" is "the fact is about the world, not the code",
the *replacement* obligation is heavier than it looks: run the command, paste what it printed, and
ask what it would print after the change you are anticipating. Prose is not exempt from §16 — a
guard whose corpus can silently shrink is the same defect whether the corpus is a file walk or a
reader's ability to reproduce a number.

This is a stopgap and should be labelled one. **The durable fix is a `required_status_checks` rule,
which is a repository setting and the owner's to add** — tracked on #30. Until it exists, the
sentence to keep in mind is that a discipline nobody has written down is one review round from being
dropped, and this one is currently load-bearing for every check this document argues for.

## 21. A mutation that applies is not yet the counterfactual

§19 asks which guard produced the red. This asks the question before that one: **is the mutation
you ran the defect you meant to model?**

Two different claims get made by one step, and they are not equally checkable:

- **"the mutation landed."** Mechanical. Assert the anchor matched exactly once and that the tree
  still builds — `[build failed]` contains the substring `FAIL`, so an unbuildable mutant reads as
  a red test.
- **"the mutation is the counterfactual."** A judgement about whether the mutated code is what
  existed before the fix. Nothing asserts it, and the assertion above says nothing about it.

Conflating them is how a falsification gets recorded for a mutation that compiled, applied, and
tested something else. **The rule underneath every instance below: the mutation must make the guard
ADMIT the input under test.** Not "disable something near the guard" — admit that input, and change
nothing else.

### It left the real branch running

Three instances in one day, every one with the same signature: the anchor matched, the tree built,
the test stayed green, and the reason had nothing to do with the change.

- Falsifying "the report is uploaded" by **renaming the upload step**. `actions/upload-artifact`
  and its paths were untouched, so the check passed while the mutation was live.
- Falsifying a corpus guard by removing **one of two** invocations of the tool it looks for. The
  other still satisfied it.
- Falsifying build-failure handling by inserting `continue` after the `Test` check — while the
  build-event branch **earlier in the same loop** still ran. The report stayed red, for a reason
  unrelated to the mutation: a wrong detector inside a wrong counterfactual.

The shape is always the same. **Inserting a disable turns off *a* branch; the defect was the
absence of *all* of them**, and the fixed code has structure the earlier code did not.

### It disabled far more than the guard

The same rule violated from the other side, and it depends on the guard's **polarity**. Every
worked example in this file is a *refusal* guard — `if bad { return err }` — where `if false && (…)`
isolates it correctly. On an *admission* predicate the same operator does the opposite: it makes the
function reject everything.

Measured on `permitsClientAuthentication` (`internal/auth/auth.go`), whose body is
`if usage == ExtKeyUsageClientAuth || usage == ExtKeyUsageAny { return true }`:

Counts below are **top-level test functions**, produced from the `kms` module root by:

```
rc=0; go test ./... > run.log || rc=$?                  # || so set -e cannot abort here
count=$(grep -cE '^--- FAIL: ' run.log || true)         # -c exits 1 on zero matches
echo "exit=$rc failures=$count"
```

Every guard here is load-bearing and none was in the first version of this block. Under `set -e`
both commands abort the script, at opposite ends of the range: a failing `go test` aborts before
`rc=$?` can run, so the interesting case is lost, and `grep -c` exits **1 when the count is 0**, so
the unguarded form aborts on a *healthy* tree. `rc` is seeded to 0 and assigned through `||` rather
than from `$?` on the next statement, because any command in between overwrites `$?` — including an
`echo` that prints it.

That this four-line block needed five corrections is the section's own argument: each earlier
version produced the right number on the tree it was written against and was wrong about a case
nobody had built.

The `^` anchor is the whole point: without it the same run counts subtests too and gives roughly
double. The count is taken from a **file, with the exit status read separately**, because a count
alone cannot distinguish a passing tree from one that did not compile — both give 0, since a
compiler error does not match `^--- FAIL:`. Nonzero exit with a zero count is the build-failure
signature. Do not fold stderr into the pipe to fix this: it does not change the count, and
`grep -c` then swallows the compiler error that was the only visible sign of the problem.

The unit is spelled out because two of us measured this table on the same day and disagreed
**54 against 99** purely on that choice, in the middle of an audit whose subject is numbers that
stop meaning what they said. The same narrowing run counted four ways: 54 top-level functions,
99 `--- FAIL` lines, 54 distinct function names, 5 packages.

| Mutation | Result (measured 2026-09-07) |
|---|---|
| narrowing — `if false && (usage == … \|\| usage == …)` | **54 functions red across 5 packages**, attributing nothing |
| widening — `if true \|\| (usage == … \|\| usage == …)` | **1 function red**, the sole detector — `TestPermitsClientAuthenticationRejectsWrongPurposeEKU` |

This is a dated demonstration, not an inventory: re-run it rather than trusting the figures. The
narrowing count was 14 when first written and is 54 now, purely because the tree gained tests — the
asymmetry is the claim, and it got stronger. The widening count has not moved from 1, and it is the
one that would actually falsify the section if it did.

The same applies to a conjunct inside a returned expression, as in `canonicalURISAN` in that file.
Only the widening form makes the guard admit the input under test; the narrowing form makes the
function refuse everything, and a suite that refuses everything fails broadly and says nothing.

**A mutation that reds more than a couple of tests is almost certainly the wrong polarity, not
thorough coverage.** Broad red reads as "well covered" and names no defect — §19's failure with the
blast radius reversed.

### How to build one that is the counterfactual

**Revert; do not insert.** Take the earlier implementation — `git show HEAD~1:<path>`, or delete
the whole hunk the fix added — rather than adding a disable to the current code. Reverting cannot leave
a sibling branch running, because there is no sibling branch to leave.

Then read the failure text before believing it, per §19. If a mutation leaves the test green, there
are two candidate explanations and they need different fixes: the test cannot fail (§16, §18), or
the mutation is not the defect. Ask whether the mutated code equals what existed before the fix. If
that cannot be answered from the diff, the answer is no — revert the hunk instead.

### And the counterfactual is not the premise

Everything above is about getting the mutation right. There is a boundary past which a correct
mutation still proves nothing, and it is worth stating because the method reads as complete without
it.

**A falsification asks "does this test catch the absence of this code?" It never asks "should this
code exist?"**

Worked example, from the same day as the instances above. `envelope.validateEnvelope` accepted a
16-byte ciphertext while both seal entry points refuse anything under 17 — the parser accepting a
shape the writers cannot produce, which is a real and productive family. A guard was written, a
four-row table with an ANCHOR row, and the mutation reverted the floor: **exactly one row flipped,
cleanly attributed.** A textbook falsification by every rule in this document.

The change was still wrong. An empty-plaintext envelope is already refused one layer up by
`Releaser.Execute` with `"envelope released an empty secret"`, and that error's *identity* is
load-bearing — `Coordinator.execute` branches on `errors.Is(err, ErrInvalidEnvelope)` to answer
INVALID_ARGUMENT and to record the audit outcome `"integrity-failed"`. Raising the floor would have
relabelled a well-formed, authentic envelope that happens to hold nothing as an **integrity
failure**, and taken from the operator the one error that says what actually happened.

**A well-built falsification of a change that should not be made proves the change works, not that
it is right.** The counterfactual was correct; the premise was not, and nothing in the falsification
protocol inspects the premise.

What caught it was `go test ./...` — a package the change did not touch. The guard, the rule that
makes the guard correct, and the test that owns that rule were in **three different packages**, and
`TestAnEnvelopeWhoseCiphertextIsOnlyATagReleasesNothing` was **hours old**, added by the guard sweep
in #238 that morning. Before that commit the rule existed in one `errors.New` and nowhere else, and
the change would have shipped.

So, before falsifying a change:

- **Ask what already enforces this rule, and where.** Grep the error string and the behaviour, not
  just the function you are editing — a rule enforced at a different layer will not appear in the
  package you are reading.
- **Run the whole tree, not the package you touched**, even for a one-character change. The
  distance between the operand and its owning test is exactly the distance a premise error hides in.
- When an asymmetry looks like an oversight, **assume it may be load-bearing until you find where it
  is decided**. If the reason is not near the code, that is §14, and the durable fix is a comment at
  the operand — not the change that looked obvious.
## 22. The guard checked a proxy that the failure also satisfies

§16 is about a guard whose corpus the same bug shrinks. This is its sibling one level down: the
guard asks a question that is *near* the property, and the failure answers it the same way a
success does.

The tell is always the same sentence. **A file existing is not a run having happened.** Neither is a
report with nothing in it, a value that is not `None`, or an exit code of zero from a step that
produced no evidence.

The instances below come from two tools and one sweep. Every one was found by running the thing
rather than reading it, and every one had a **correct** exit code — so the only wrong artifact was
the one the guard existed to protect:

| The guard asked | The property was | How the failure satisfied it |
|---|---|---|
| `if blob is None` | did the read succeed | a failed `git show` returns `b""`, which is not `None` |
| `test -s report.xml` | did the suite run | a converter that ran and wrote an empty report leaves a file |
| `0 tests, 0 failed` → exit 0 | did any test execute | a tree that does not compile emits no `Test` events at all |
| a non-empty input file | did the command produce output | a run that died before writing emits an empty stream |

The two report rows are the sharpest, because `test -s` was added **specifically** to catch them
and could not see either. It was written as the net for a converter that failed silently — and a
converter that emits a well-formed report saying nothing happened passes it, as does one that
emits a report for a tree which never compiled. **A guard built for a class can be blind to that same class one field
further out**, because the proxy it chose is produced by the failure too.

**The same substitution reaches the sweeps that look for it.** Auditing this repository for
decoders that accept trailing bytes, I counted *files* containing a decoder against *files*
containing an EOF check, and reported the estate almost clean. The unit was wrong:
`internal/approval/approval.go` held **two** decoders and **one** check, so per-file granularity
counted it as covered and hid the very defect the sweep existed to find — and the decoder it hid was
the second of the two the sweep eventually reported.

**The census that sweep produced is deliberately not repeated here, and it was worse than stale.**
Both findings were fixed within the day, so any number would be a claim about a tree that no longer
exists. But writing a recount to replace it turned up something worse: **the original count was
produced by a heuristic that conflated two meanings of the same token.**

The sweep asked whether `io.EOF` appeared near each decoder. It appears in two unrelated roles:

```go
if err := decoder.Decode(&extra); !errors.Is(err, io.EOF) { …   // a trailing-data guard
if err := decoder.Decode(&record); errors.Is(err, io.EOF) { …   // a JSONL loop terminator
```

A loop that reads records until end-of-stream is *supposed* to reach `io.EOF`; it has no trailing
data to reject. So the original "checked" count included decoders for which the question does not
arise — and the guard, planted with a real gap, reported the tree clean, because the loop's own
terminator sat inside the window it searched.

> **Observed 2026-09-07, by reading each site:** of the 20 decoders then present, 9 were stream
> loops and 11 single-document reads. Recorded as an **observation with a date, not a property of
> the repository** — the totals will drift, and the paragraph below says why they cannot be
> re-derived by a command. It is here because a section asserting that a proxy and a property come
> apart should show a tree where they did; a reader who counts differently should trust their own
> reading over this sentence, and the claim it supports survives either way.

That is this section's subject, in the sweep that produced this section: **the proxy was "`io.EOF`
appears nearby", the property was "trailing data is rejected", and a JSONL loop satisfies the proxy
without having the property.**

So the durable part is the unit, and only the unit:

```
grep -rn  "json.NewDecoder" --include="*.go"  | grep -v _test | wc -l   # decoders
grep -rln "json.NewDecoder" --include="*.go"  | grep -v _test | wc -l   # files
```

Two files with one decoder each and two files with two are the same number of files and a different
number of decoders. Run both and read the gap: **a difference is the number of decoders the per-file
view would have hidden, and equality is a claim that every file holds exactly one** — true today or
not, but a claim to check rather than a result to accept, since it is also what the count returns
when the pattern has stopped matching. **Which decoders are actually guarded is
not greppable** — it needs the reader to know whether each one reads a document or a stream, and any
one-line recipe offered here would be the same conflation with a different spelling.

A corpus guard counting the wrong unit, inside the instrument that was looking for that class. The
proxy was "this file is covered" and the property was "this decoder is checked".

### How to find them

Ask what the failure you are guarding against would *leave behind*, and then check whether the guard
would accept it. Not "does this detect the bug I have in mind" — the bug you have in mind is the one
you designed the proxy around.

- `x is None` / `x != nil` / `len(x) > 0` on a value a **failed** call also returns. Check the
  status the call actually reports: a `returncode`, an `error`, an `ok` flag.
- File existence, non-empty file, "the artifact uploaded". All of them are satisfied by a process
  that started, did nothing useful, and exited.
- A count that a total failure drives to zero, where zero is also a legitimate answer. Say which
  zero you mean, and refuse the other — `tools/junit.py` refuses an empty event stream rather
  than reporting it as a suite with no tests.

### What to write instead

Assert the **positive** fact, not the absence of a negative one. "The report names at least one
package" is a claim a broken run cannot satisfy; "the report exists" is a claim it satisfies by
accident. Where the positive fact is genuinely unavailable, say so in the failure message, so the
next reader knows the guard is a proxy and which one — a proxy chosen deliberately is a different
thing from a proxy mistaken for the property.

## Delete the duplication; pin it only when you cannot

The recurring defect in this repository is one rule stated in more than one place. The capability
matrix in Go and Python (#73), the OpenAPI document against the router (#72), the custody rules in CI
against the daemon (#78), and "an https origin" — which is on its *third* statement: `ValidateSinkURL`
against the SOPS adapter's `loadConfig` (#93), and then the Ansible role's `audit_sink_url` regex,
which nobody had looked at when those two were reconciled (#88). In every case they had **already
drifted** by the time anyone looked.

That third one also argues for the format. Review reported the role as *stricter* than the daemon: it
rejected a trailing slash. Writing out what the rule must accept and refuse showed it was
simultaneously *looser* — the character class `[^/@:]` admits `?` and `#`, so the role accepted
`https://collector.internal?a=b`, which the daemon refuses to start on. One character class, wrong in
both directions, and a regex read by eye hides both. Enumerating the cases surfaced the error nobody
had reported.

**The first question is whether they can be merged, and usually they can.** Review of #87 found
`telemetry.Path` and `server.MetricsPath` both holding `"/v1/metrics"` in the same module, each
comment claiming to be the single definition, and nothing preventing one from being merged into the
other. It was: `main` declares the string once, in `server.MetricsPath`, and `telemetry.Path` is now
`const Path = server.MetricsPath` — an alias, so the name each package reads is still local but there
is only one definition to change. A mirror test would have been the expensive answer, and it would
have left a second definition in place for someone to edit.
Writing a test to hold two constants in agreement, when one `const` would do, is the expensive answer
to a cheap problem, and it leaves the second definition there for someone to edit.

Only when they genuinely cannot be merged does the technique below apply. The SOPS adapter is a
separate module that cannot import `internal`; the Python validator cannot call Go. There the fix
is not one implementation but **two implementations asserted against one table** — each test running
its own real loader rather than a copy of its rule, and each implementation's comment naming the
other, so a reader knows there are two and that changing one means changing both.

Then test the *relationship*, not either side. `TestManifestKEKVersionsAreNameableByAnEnvelope` takes
a list of candidate versions and requires the manifest loader and the envelope's KEK reference to
agree on each — it asserts nothing about what either pattern is, only that they cannot disagree.
Widening one half makes it report the values a manifest would accept and no envelope could carry.

A mirror test is a fallback for an unbridgeable boundary. It is not a substitute for deleting the
duplicate.

## Verified once is not verified now

A claim checked when it was written can be false by the time it is read, and neither the test nor the
citation will say so.

**Re-falsify after a rebase.** A merge can leave a test green and hollow, because the thing it was
installed to observe has moved. `TestTheRequestPathEmitsNoLogs` (#95) asserts the request
path emits no logs; #87 then put a metrics collector inside that path. The test still passed — and "it still
passes" and "it still means something" are different claims. Re-running its falsification after the
rebase is what established the second. Nobody does this and everybody should: the cost is one
command, and the alternative is a guard that stopped guarding at a merge nobody associated with it.

**Quote the ref, not just the line.** Line numbers move — the fencing render in §8 moved twice while
this document was open — so cite the symbol and the file. Branches are worse, because two people
reading honestly can reach opposite conclusions from different trees: one of us here reported that
`envelope.ReleaseContext` existed and the other greped for it and found nothing, both correct, on
different branches. Where a claim depends on a tree that is not `main`, name it, as the #87 and #88
examples above do.

I got this wrong in this document twice, and the second time the *checker* was wrong. Every
identifier here is verified by grepping the tree — and the grep matches this file, which cites them
all. So an identifier existing nowhere but this document reported as found.

**A verifier whose search space includes the artifact under test confirms every claim, including the
false ones.** That is not a documentation quirk. It is the shape of any check that looks for evidence
in a corpus containing the assertion: a grep for a symbol across a tree that holds the file claiming
the symbol exists, a config audit that reads the file it is validating, a link checker that counts a
document's own anchors. Exclude the artifact from its own search space, or the result is a
tautology wearing the costume of a search.

The first time was simpler: one filename, taken from a review message and cited without looking, in a
document about claims nobody checked. It was real, on a branch, and a reader on `main` could not have
found it.

## Do not hide from the instrument

Fixing #88, the secret scanner flagged a deployment-verification script — on branch
`ops/kms-ansible-hardening`, not yet on `main` — for containing the PEM headers it exists to hunt
for. The file holds no secret, so composing the headers from parts in the script was
legitimate. The test then pinned the expected headers base64-encoded, on the reasoning that gitleaks
matches literal text. It decodes base64 and found them anyway — correctly.

The lesson is not that base64 does not work. It is that the second step was concealment reached for
to make a check stop firing, and when the instrument defeated it the honest fix turned out to be
better than the one being attempted: derive the headers from `ssh-keygen` and `openssl` at run time
and assert *those* are refused, which tests the scanner against real key material rather than a
literal.

Anything written to make a check stop firing deserves the question of whether it fixes the code or
hides from the instrument. An instrument that can be talked out of firing is not measuring anything,
and the moment it defeats a workaround is a good moment to ask what the workaround was for.

## The number is a bad summary of the work

Covering `server.RequireAll` — the composition deciding whether the daemon serves at all, with no
branch of it exercised: empty composition, nil probe, cancelled context, panicking probe, every one
a fail-closed guard — moved total coverage from 68.8% to 69.0%. The functions went from 0% to 100%.
Optimising the total would have pointed at hardware-gated PKCS#11 paths instead, which is the
opposite of where the risk was.

**And the measurement can under-report, which is the mirror of a false green.** A first read showed
`auth.LoadPolicyFile` at 0% and nearly produced tests for it. It is called by `preflight`, which is
tested — Go attributes coverage per package unless you pass `-coverpkg`, so cross-package exercise
reads as zero, and a separate module reads as zero twice over. A false green stops you looking
where you should; a false red sends you to write tests for code that is already tested. That one
was caught only because 0% on a security-relevant loader was surprising enough to check, which is
not a method.

**A build tag makes the number lie in the other direction, and harder.** `go test ./...` does not
compile tagged files at all, so their statements are absent from the denominator rather than counted
as uncovered. Measured on the same tree:

| package | `go test ./...` | with the gate opened | error in the default figure |
|---|---|---|---|
| `internal/backend/yubikey` | 83.8% | **46.2%** (`-tags piv`) | overstates by 37.6 points |
| `internal/backend/nitrokey` | 70.4% | **79.0%** (SoftHSM battery) | understates by 8.6 points |

Two packages, one command, opposite directions. The yubikey figure is the dangerous one: at 83.8% it
reads as better covered than several packages that are genuinely well tested, so anyone choosing
work by the number is steered away from the weakest package in the module — whose entire PIV driver
is at 0.0%. The nitrokey figure is the same mechanism pointed the other way: its concrete driver is
exercised only by an env-gated battery, so optimising 70.4% means writing tests for code the e2e
already covers.

**And past a point the number stops indicating anything at all.** `internal/fencing` (86.9%),
`internal/audit` (87.2%) and `cmd/regalia-kms`'s `preflight` (66.3%) were audited looking for
unchecked properties and had none: every property their comments claim is already pinned by a named
test — `TestAFailedWriteLeavesThePublishedLeaseIntact`, `TestNoTemporarySurvivesAFailedWrite`,
`TestForgedShippedMarkIsRefused`, `TestVerifyPolicyStateRefusesATruncatedJournal`. What is uncovered
in them is error-path plumbing that needs filesystem failure injection, and `preflight`'s 66.3% is
the lowest of the three while being the most thoroughly defended. A low number there is not a gap
and a high number elsewhere is not assurance.

Use coverage to find the zeroes and then look at them — and check whether a gate is hiding the
denominator before believing either the zero or the total. The percentage is not the deliverable and
moving it is not the work.

## Writing the failure message

The message is the deliverable of a failing test. It is read by someone who does not have the context
you have now, at the moment something breaks. State what was observed, what was expected, and what it
would mean in production:

```
a release-secret binding with kek_algorithm "" was accepted: this object would be
commissioned and then fail at its first release, forever, as a retryable error
```

`t.Fatal("kek_algorithm not required")` would have been true and useless. The reader already knows
which assertion failed; what they need is what it costs.
