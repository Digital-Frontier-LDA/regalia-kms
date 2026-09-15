package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"regexp"
	"time"
	"unicode/utf8"
)

// THE SCHEMA HOLDS REFERENCES, NEVER CONTENT, AND THAT IS ENFORCED BY THREE THINGS TOGETHER.
//
// #33 says "store metadata and public identifiers only -- never secret values". A schema that
// says so in a comment has said nothing: the field that accepts prose accepts a private key, and
// the reviewer who pastes one is not reading the comment. Three mechanisms carry the rule instead,
// and none of them is advisory:
//
//  1. THERE IS NO FIELD FOR CONTENT. Every field below is either a member of a closed enumerated
//     set (class, environment, rotation, custody, and the scheme half of location) or a reference
//     to a thing that lives somewhere else (system id, owner handle, the reference half of
//     location, the exception's approver and tracking id). There is no `value`, no `notes`, no
//     `description` -- nothing whose purpose is to hold text. The registry's custodyObject has a
//     free-text `notes`; this record deliberately does not, because an inventory is read by a
//     scanner and a manifest is read by a daemon.
//
//  2. AN UNKNOWN FIELD IS REFUSED, NOT IGNORED. This is the half that a Go struct does not give
//     you for free, and without it mechanism 1 is decorative. encoding/json silently discards a
//     key with no matching field, so a record carrying `"value": "hunter2"` would decode clean,
//     the tool would report the file verified, and the secret would sit in the committed file
//     exactly as written. DisallowUnknownFields turns that silent discard into a refusal -- and it
//     is set on the nested Exception decoder too (see Exception.UnmarshalJSON), because a custom
//     UnmarshalJSON does NOT inherit the parent decoder's setting and the nested object would
//     otherwise be the one hole left in the file.
//
//  3. EVERY STRING IS LENGTH-CAPPED at maxFieldBytes, which is smaller than any credential class
//     this inventory covers -- a PEM block, an armoured key, a JWT, a cloud provider's service
//     account JSON. The cap is checked before the pattern, so the refusal names the size rather
//     than emitting a hundred-kilobyte "does not match" message.
//
// WHERE THIS STOPS, STATED PLAINLY RATHER THAN LEFT FOR SOMEONE TO DISCOVER. A short secret typed
// into a reference field is still bytes in a file, and no schema can prevent that: `owner` accepts
// `@hunter2` and a six-character password is a valid-looking handle. What these three mechanisms
// remove is the field that INVITES a value and the unknown key that SMUGGLES one. They do not make
// the file incapable of holding a short string that happens to be a credential. The control for
// that is the secret scanner over the whole repository, which is a different tool with a different
// failure mode, and this comment exists so nobody reads "structurally impossible" as "scanned".
const (
	// maxDocumentBytes bounds the file. The registry caps its manifest at 2 MiB; an inventory of
	// references is far smaller, and a file this size is a sign that someone pasted material in
	// rather than a sign of a large estate.
	maxDocumentBytes = 1 << 20

	// maxFieldBytes is the per-string cap described above. 128 bytes holds any identifier, handle
	// or path reference in this repository and holds none of the credential shapes the inventory
	// is about.
	maxFieldBytes = 128

	// schemaVersion is the only version this tool reads. A document declaring anything else is
	// refused rather than read on a best-effort basis: a field this tool does not know about is a
	// custody decision it cannot check, and reading it anyway would report a verified inventory
	// over rules that were never applied.
	schemaVersion = 1

	// dateLayout is the only accepted spelling of a date, matching tools/custody_manifest.py
	// so the two tools cannot disagree about what a date is.
	dateLayout = "2006-01-02"
)

// THE VOCABULARY BELOW IS NOT THIS TOOL'S TO INVENT.
//
// class, environment and custody are the SAME sets the custody manifest publishes in
// config/custody-manifest.schema.json ($defs.custodyObject.properties.{kind,environment,
// custody}). Copying the values here rather than importing them is forced -- the loader's copies
// in internal/registry are unexported -- so the binding is held by a test instead:
// TestVocabularyMatchesThePublishedCustodySchema reads the schema file and compares the sets.
//
// The reason to share them at all is that a secret does not change class when it becomes a KMS
// object. An inventory record saying `api-token` and a manifest object saying `api-token` must
// mean the same thing, or the migration from one to the other is a translation step where facts
// get lost. This repository has already paid for the alternative once: bindingStates was an inline
// `!=` chain, adding "revoked" updated the chain and left the schema and the Python validator
// behind, and the daemon accepted a manifest CI refused.
//
// rotationMethods and storageSchemes have no counterpart in the manifest and are inventory-only.
var (
	// secretClasses mirrors the manifest's `kind`.
	secretClasses = map[string]struct{}{
		"asymmetric-key": {}, "symmetric-key": {}, "opaque-secret": {}, "password": {},
		"api-token": {}, "seed": {}, "certificate": {}, "fido-credential": {}, "sops-recipient": {},
	}
	// environments mirrors the manifest's `environment`.
	environments = map[string]struct{}{
		"production": {}, "staging": {}, "development": {},
	}
	// custodyModes mirrors the manifest's `custody`, and is the closed set of four classifications
	// #33 requires: direct hardware, KMS envelope (spelled hardware-envelope, as the manifest
	// spells it), FIDO multi-enrollment, and a documented time-bounded exception.
	//
	// CLOSED IS THE WHOLE POINT. A fifth value cannot be added by a document; it can only be added
	// here, next to the rule that an exception carries an expiry, where whoever adds it has to say
	// what continuity the new mode provides.
	custodyModes = map[string]struct{}{
		"direct-hardware": {}, "hardware-envelope": {}, "fido-multi-enrollment": {}, "exception": {},
	}
	// rotationMethods says HOW the secret is rotated, not when.
	//
	// "undetermined" is deliberately a member. The instinct is to leave it out so that every record
	// must state a real method, but a set with no way to say "nobody has worked this out yet" does
	// not produce inventories where everything is known -- it produces inventories where the
	// unknown ones are quietly written down as `manual-ceremony`. #33's fifth acceptance criterion
	// asks for the opposite: missing owners and inaccessible systems must be VISIBLE blockers
	// rather than silently omitted. So the gap is spellable, and Report counts it (Blockers) and
	// prints it, which is what makes it visible. It does not refuse the run, because a blocker that
	// fails the build gets deleted rather than fixed.
	rotationMethods = map[string]struct{}{
		"manual-ceremony": {}, "provider-automated": {}, "hardware-regenerate": {},
		"not-rotatable": {}, "undetermined": {},
	}
	// storageSchemes is the closed set of places a secret can currently live. It is the first half
	// of `location`, and it is an enum precisely so that "where is this thing" cannot be answered
	// in prose -- see mechanism 1 above.
	storageSchemes = map[string]struct{}{
		"hardware": {}, "envelope": {}, "sops": {}, "saas": {}, "ci": {}, "paper": {},
	}
)

var (
	// identifierPattern is a lowercase identifier, and it is DELIBERATELY NOT the registry's.
	//
	// internal/registry uses `^[a-z0-9][a-z0-9-]{2,62}$` (exported as registry.MatchesIdentifier)
	// and the two differ in both directions, so neither is a superset of the other:
	//
	//	ci          valid here, refused there   an inventory names systems like ci and dns; a
	//	                                        three-character minimum is a manifest's rule about
	//	                                        object ids, not a fact about what systems are called
	//	forge--a-   valid there, refused here   a doubled or trailing hyphen is a typo, and an
	//	                                        inventory is a list of names people read
	//
	// Saying this rather than claiming a match, because an earlier draft of this comment asserted
	// the two shapes were the same. They are not, and a comment that describes a binding nothing
	// checks is how the copies in this file would have started drifting on day one. The length
	// bound the registry folds into its pattern is carried here by maxFieldBytes.
	identifierPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*$`)
	// ownerPattern accepts a handle or a team path: @jobordu, @df/security.
	//
	// AN OWNER IS A HANDLE, NOT A NAME, because the verifier's job is to make an unowned secret
	// refusable and a person's name is not addressable. "Security team" cannot be paged.
	ownerPattern = regexp.MustCompile(`^@[a-z0-9]+(-[a-z0-9]+)*(/[a-z0-9]+(-[a-z0-9]+)*)?$`)
	// locationReferencePattern is the second half of `location`, after the scheme. It is broad
	// enough for a path, a slot, or a vault item, and it excludes whitespace and quotes so that a
	// pasted blob does not fit.
	locationReferencePattern = regexp.MustCompile(`^[A-Za-z0-9._/#@-]+$`)
	// trackingPattern points at the issue where the exception was argued: repo#number.
	//
	// The exception carries a POINTER to the reasoning rather than the reasoning itself. That is
	// mechanism 1 again -- a free-text `reason` would be the one field in this schema that accepts
	// prose, and therefore the one field that accepts a private key -- but it is also the better
	// record: an exception's justification changes, and a copy pasted into an inventory does not.
	trackingPattern = regexp.MustCompile(`^[a-z0-9]+(-[a-z0-9]+)*#[1-9][0-9]{0,6}$`)
)

// Date is a calendar date that cannot be constructed from JSON except by parsing one.
//
// It is a struct wrapping an unexported time.Time rather than a named string type, so that a
// caller cannot write Date("whenever") and a zero value is distinguishable from a parsed one.
type Date struct {
	t time.Time
}

// UnmarshalJSON is the only way a Date is produced from a document, and it accepts exactly one
// spelling. A date is not a place to be lenient: "01/02/2026" is ambiguous between two continents,
// and an expiry read a year wrong is an exception that outlives its approval.
func (date *Date) UnmarshalJSON(data []byte) error {
	var text string
	if err := json.Unmarshal(data, &text); err != nil {
		return fmt.Errorf("must be a JSON string holding a %s date", dateLayout)
	}
	parsed, err := time.Parse(dateLayout, text)
	if err != nil {
		// clip: `expires` is caller-supplied and nothing has bounded it at this point.
		return fmt.Errorf("%q is not a %s date", clip(text), dateLayout)
	}
	date.t = parsed
	return nil
}

// String renders the date back in the layout it was parsed from, for refusal messages.
func (date Date) String() string { return date.t.Format(dateLayout) }

// Before reports whether this date falls before the given day.
func (date Date) Before(day time.Time) bool { return date.t.Before(day) }

// Exception is the "documented time-bounded exception" custody classification, and IT CANNOT BE
// BUILT WITHOUT AN EXPIRY.
//
// #33 exists because unmanaged credentials persist. An exception with no end date is not a weaker
// form of custody, it is the failure the issue is about, wearing the word "documented". So the
// expiry is not a validation rule that a later refactor can drop -- it is a property of the type:
//
//   - Every field is UNEXPORTED. Nothing outside this file can build an Exception at all, by
//     composite literal or otherwise, so there is no route that bypasses the decoder.
//   - UnmarshalJSON is the only writer of `expires` in the package, and it refuses a document that
//     omits the field. Note the shadow struct uses *Date, not Date: with a plain Date, an absent
//     key and `"expires": null` both leave the zero value, and the rule would be enforced by
//     comparing against a zero time rather than by observing that nothing was supplied. A pointer
//     distinguishes absent from present, which is the same trap Go's JSON handling sets for every
//     optional field in this repository.
//
// Together those mean a *Exception that exists has an expiry, and the verifier's remaining job is
// to check that the expiry has not passed -- a question about today, not about the document.
//
// The nested decoder sets DisallowUnknownFields for the reason given in mechanism 2 at the top of
// this file: a custom UnmarshalJSON receives raw bytes and inherits nothing from the outer
// decoder, so without this line the exception object is the one place in the schema where an
// unknown key is silently dropped.
type Exception struct {
	expires    Date
	approvedBy string
	tracking   string
}

// UnmarshalJSON decodes an exception, refusing one that does not carry all three of its fields.
func (exception *Exception) UnmarshalJSON(data []byte) error {
	var raw struct {
		Expires    *Date   `json:"expires"`
		ApprovedBy *string `json:"approved_by"`
		Tracking   *string `json:"tracking"`
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&raw); err != nil {
		return err
	}
	if raw.Expires == nil {
		return fmt.Errorf("exception requires %q: an exception with no end date is the condition this inventory exists to remove", "expires")
	}
	if raw.ApprovedBy == nil {
		return fmt.Errorf("exception requires %q: an exception nobody approved is an omission with a label", "approved_by")
	}
	if raw.Tracking == nil {
		return fmt.Errorf("exception requires %q: the reasoning lives in the tracked issue, and a record that does not name it cannot be reviewed", "tracking")
	}
	exception.expires = *raw.Expires
	exception.approvedBy = *raw.ApprovedBy
	exception.tracking = *raw.Tracking
	return nil
}

// Expires reports the day the exception lapses.
func (exception *Exception) Expires() Date { return exception.expires }

// ApprovedBy reports the handle that approved the exception.
func (exception *Exception) ApprovedBy() string { return exception.approvedBy }

// Tracking reports the issue reference where the exception was argued.
func (exception *Exception) Tracking() string { return exception.tracking }

// System is a named system that holds secrets, and the owner accountable for it.
type System struct {
	ID    string `json:"id"`
	Owner string `json:"owner"`
}

// Record is one secret, described by reference only. The fields are exactly the list #33's scope
// section names -- system, secret class, owner, environment, rotation method, current storage
// location -- plus the assigned custody and, when that custody is an exception, its terms.
type Record struct {
	ID          string     `json:"id"`
	System      string     `json:"system"`
	Class       string     `json:"class"`
	Owner       string     `json:"owner"`
	Environment string     `json:"environment"`
	Rotation    string     `json:"rotation"`
	Location    string     `json:"location"`
	Custody     string     `json:"custody"`
	Exception   *Exception `json:"exception,omitempty"`
}

// Document is one inventory file.
type Document struct {
	SchemaVersion int      `json:"schema_version"`
	InventoryID   string   `json:"inventory_id"`
	GeneratedAt   *Date    `json:"generated_at"`
	Systems       []System `json:"systems"`
	Records       []Record `json:"records"`
}

// Refusal is one reason the inventory was not accepted, addressed to whoever has to fix it.
type Refusal struct {
	Where  string
	Reason string
}

func (refusal Refusal) String() string { return refusal.Where + ": " + refusal.Reason }

// Report is the outcome of one run. The verdict is derived from it and is never stored, so there
// is no way to construct a Report that carries refusals and reports success -- see Verdict.
type Report struct {
	Systems  int
	Records  int
	Errored  int
	Blockers int
	Refusals []Refusal
}

// Verdict is the single place the words "verified" and "refused" are chosen, and it chooses by
// looking at the refusals.
//
// THIS FUNCTION EXISTS BECAUSE OF A REAL FAILURE IN THIS REPOSITORY, NOT AS A STYLE PREFERENCE. A
// sibling tool exited 0 and printed a sentence asserting a property of files it had never opened:
// it matched zero files, and its summary line was a constant. The lesson is not "check for zero
// files", it is that a success sentence must not be printable on a failing run -- so the string is
// computed from the outcome rather than written next to the code that hopes for it.
//
// Pinned by TestVerdictIsAFunctionOfTheRefusals.
func Verdict(report Report) string {
	if len(report.Refusals) == 0 {
		return "VERIFIED"
	}
	return "REFUSED"
}

// OK reports whether the run may exit zero.
func (report Report) OK() bool { return Verdict(report) == "VERIFIED" }

// refuse records one refusal.
func (report *Report) refuse(where, format string, args ...any) {
	report.Refusals = append(report.Refusals, Refusal{Where: where, Reason: fmt.Sprintf(format, args...)})
}

// clip bounds caller-supplied text before a refusal quotes it.
//
// UNVALIDATED INPUT REACHING OUTPUT IS THE DEFECT CLASS THIS FILE KEEPS PRODUCING, and this is the
// third instance found. The first was `location`, whose length cap no fixture reached. The second
// was the record id landing in the refusal LABEL before validation, where a newline forged a whole
// extra finding. The third was `checkEnum`, which quoted its value with no cap at all: a five
// kilobyte `class` was echoed verbatim into the report and into CI logs.
//
// Each was fixed where it was found, which is how a class gets three separate patches and no
// remedy. So the bound lives in ONE function now, and the rule is stated once: nothing
// caller-supplied is interpolated into a refusal without passing through here. The sites that
// already cap before quoting -- checkField and checkLocation, which both refuse on size before
// they ever reach the pattern message -- are unchanged, because for them the cap IS the refusal.
//
// It truncates rather than refusing on size, because for an enumerated field the accurate refusal
// is that the value is not a member; its length is beside the point. The byte count is appended so
// the message says a large value was supplied rather than silently implying a short one.
//
// The cut lands on a rune boundary. %q would render a split rune as an escaped byte, which is not
// wrong, but a report a person reads should not contain debris that looks like the data.
//
// WHAT THIS DOES NOT DO: it does not stop a secret SHORTER than the cap from being echoed. A
// pasted credential of forty characters is quoted in full, exactly as checkField quotes a
// malformed owner. That is the same trade every validator makes -- a refusal that will not say
// what it refused cannot be acted on -- and it is why the premise of this tool is that the schema
// has nowhere to STORE a value, not that the report is redaction.
func clip(value string) string {
	if len(value) <= maxFieldBytes {
		return value
	}
	cut := maxFieldBytes
	for cut > 0 && !utf8.RuneStart(value[cut]) {
		cut--
	}
	return fmt.Sprintf("%s… (%d bytes total)", value[:cut], len(value))
}

// checkField holds the three things every reference field must be: present, bounded, and shaped.
//
// They are three separate branches on purpose. "owner is required" and "owner is not a handle" are
// different problems for the person fixing the file, and collapsing them into one message makes an
// empty string report as a malformed one.
func checkField(report *Report, where, field, value string, pattern *regexp.Regexp) bool {
	if value == "" {
		report.refuse(where, "%s is required", field)
		return false
	}
	if len(value) > maxFieldBytes {
		report.refuse(where, "%s is %d bytes, over the %d-byte cap", field, len(value), maxFieldBytes)
		return false
	}
	if !pattern.MatchString(value) {
		report.refuse(where, "%s %q does not match %s", field, value, pattern)
		return false
	}
	return true
}

// checkEnum holds a field to a closed set.
func checkEnum(report *Report, where, field, value string, allowed map[string]struct{}) bool {
	if value == "" {
		report.refuse(where, "%s is required", field)
		return false
	}
	if _, ok := allowed[value]; !ok {
		// clip, not raw: this is the site that echoed a five-kilobyte class field verbatim.
		report.refuse(where, "unsupported %s %q", field, clip(value))
		return false
	}
	return true
}

// checkLocation holds `location` to scheme:reference with the scheme from a closed set.
func checkLocation(report *Report, where, value string) bool {
	if value == "" {
		report.refuse(where, "location is required")
		return false
	}
	if len(value) > maxFieldBytes {
		report.refuse(where, "location is %d bytes, over the %d-byte cap", len(value), maxFieldBytes)
		return false
	}
	scheme, reference, found := bytes.Cut([]byte(value), []byte(":"))
	if !found {
		report.refuse(where, "location %q must be scheme:reference", value)
		return false
	}
	if _, ok := storageSchemes[string(scheme)]; !ok {
		report.refuse(where, "unsupported location scheme %q", string(scheme))
		return false
	}
	if !locationReferencePattern.Match(reference) {
		report.refuse(where, "location reference %q does not match %s", string(reference), locationReferencePattern)
		return false
	}
	return true
}

// ReadBounded reads at most one byte more than the cap, so that an over-sized file is detected
// without being loaded.
//
// os.ReadFile sizes its buffer from the file's stat and reads the lot. The cap in Verify then
// refuses the document AFTER the whole thing is in memory, which is the same shape as the enum
// gap this file already had: the bound exists, and it is applied after the damage. Pointed at a
// large file -- or at /dev/zero, or a FIFO nothing ever closes -- the tool dies or hangs before
// reaching the check that was supposed to stop it.
//
// One byte over the cap is deliberate: reading exactly maxDocumentBytes cannot distinguish a file
// that fits from one that was truncated at the limit, so the extra byte is what makes the refusal
// in Verify true rather than a guess.
func ReadBounded(path string) ([]byte, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()
	return io.ReadAll(io.LimitReader(file, maxDocumentBytes+1))
}

// Verify reads one inventory document and reports every reason it is not acceptable.
//
// It returns no error. A document that cannot be decoded is a refusal like any other, so that
// Verdict has exactly one input and there is no second path on which a summary gets printed --
// the shape that let the sibling tool report success without examining anything.
//
// `now` is a parameter rather than a call to time.Now so that the expiry rule is testable without
// waiting for a date to pass. The registry does the same thing with Registry.SetClock.
func Verify(data []byte, now time.Time) Report {
	report := Report{}
	// The message does not state the file's true size, because the caller is expected to hand this
	// a bounded read (see ReadBounded) and therefore cannot know it. A cap that reports a number it
	// had to read the whole file to learn is a cap applied after the damage.
	if len(data) > maxDocumentBytes {
		report.refuse("document", "inventory exceeds the %d-byte cap", maxDocumentBytes)
		return report
	}
	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	var document Document
	if err := decoder.Decode(&document); err != nil {
		// clip: encoding/json quotes the offending key back at you, so an unknown field with a
		// enormous name puts that name in the report.
		report.refuse("document", "%s", clip(err.Error()))
		return report
	}
	// One document per file, as internal/registry requires of a manifest. Trailing JSON is the
	// shape where a second, unreviewed set of records rides along behind the reviewed one.
	//
	// THIS WAS decoder.More(), AND More() DOES NOT ANSWER THIS QUESTION. Measured on the four
	// shapes that matter, after decoding one complete value:
	//
	//	{...}{...}     second top-level object    More()=true    caught either way
	//	{...}garbage   trailing junk              More()=true    caught either way
	//	{...}}         trailing close brace       More()=FALSE   ACCEPTED by the old check
	//	{...}          clean, or trailing space   More()=false   correctly accepted
	//
	// More() reports whether another element follows in the array or object being parsed, and it
	// answers false when it cannot lex what comes next -- so the one shape it waves through is
	// malformed trailing bytes, which is the shape least likely to be deliberate. Token() asks the
	// question actually being asked: is the stream finished? Only io.EOF means yes, and every other
	// answer, valid token or lex error, means something follows the document that nobody reviewed.
	if _, err := decoder.Token(); !errors.Is(err, io.EOF) {
		report.refuse("document", "inventory must contain exactly one JSON document")
		return report
	}
	if document.SchemaVersion != schemaVersion {
		report.refuse("document", "unsupported schema_version %d, expected %d", document.SchemaVersion, schemaVersion)
	}
	checkField(&report, "document", "inventory_id", document.InventoryID, identifierPattern)
	if document.GeneratedAt == nil {
		report.refuse("document", "generated_at is required: an inventory with no date cannot be attested to")
	}

	report.Systems = len(document.Systems)
	report.Records = len(document.Records)

	// declared maps a system id to the number of records naming it, so that both directions of the
	// referential check read off one structure.
	declared := make(map[string]int, len(document.Systems))
	for index, system := range document.Systems {
		where := fmt.Sprintf("systems[%d]", index)
		idOK := checkField(&report, where, "id", system.ID, identifierPattern)
		checkField(&report, where, "owner", system.Owner, ownerPattern)
		if !idOK {
			continue
		}
		if _, duplicate := declared[system.ID]; duplicate {
			report.refuse(where, "duplicate system id %q", system.ID)
			continue
		}
		declared[system.ID] = 0
	}

	seen := make(map[string]struct{}, len(document.Records))
	for index, record := range document.Records {
		// THE ID GOES IN THE LOCATION LABEL ONLY ONCE IT HAS BEEN CHECKED, and the ordering is the
		// whole point: the label is built before the record is validated, so an id taken on trust
		// is untrusted text interpolated raw into the tool's own output. The output is one refusal
		// per line and a person reads it to decide custody, so an id containing a newline forges a
		// line -- `"x\nsystems forge: declared but named by no record"` prints a second, invented
		// finding that looks exactly like a real one. Every other interpolation here goes through
		// %q, which escapes; this one cannot, because the label is a prefix rather than a value.
		//
		// Falling back to the bare index loses nothing: the refusal that follows quotes the id.
		where := fmt.Sprintf("records[%d]", index)
		if len(record.ID) <= maxFieldBytes && identifierPattern.MatchString(record.ID) {
			where = fmt.Sprintf("records[%d] %s", index, record.ID)
		}
		before := len(report.Refusals)

		if checkField(&report, where, "id", record.ID, identifierPattern) {
			if _, duplicate := seen[record.ID]; duplicate {
				report.refuse(where, "duplicate record id %q", record.ID)
			}
			seen[record.ID] = struct{}{}
		}
		// A RECORD WITH NO OWNER IS THE ONE #33 CALLS OUT BY NAME. An unowned secret has nobody to
		// attest to it and nobody to rotate it, which is the state the issue is trying to leave.
		checkField(&report, where, "owner", record.Owner, ownerPattern)
		checkEnum(&report, where, "class", record.Class, secretClasses)
		checkEnum(&report, where, "environment", record.Environment, environments)
		if checkEnum(&report, where, "rotation", record.Rotation, rotationMethods) && record.Rotation == "undetermined" {
			report.Blockers++
		}
		checkLocation(&report, where, record.Location)
		// A RECORD WITH NO CUSTODY ASSIGNMENT is the second refusal #33 names: a secret that has
		// been found and written down but not assigned to one of the four classifications is
		// inventory work left half-done, and it is exactly the row that a reader skims past.
		custodyOK := checkEnum(&report, where, "custody", record.Custody, custodyModes)

		if checkField(&report, where, "system", record.System, identifierPattern) {
			// A SYSTEM NAMED BY A RECORD BUT NEVER DECLARED. The record points at something the
			// document does not describe, so the secret has no owning system and the estate has a
			// hole exactly the size of whatever `system` names.
			if _, ok := declared[record.System]; ok {
				declared[record.System]++
			} else {
				report.refuse(where, "system %q is named here but not declared in systems", record.System)
			}
		}

		if custodyOK {
			switch {
			case record.Custody == "exception" && record.Exception == nil:
				report.refuse(where, "custody \"exception\" requires an exception block naming expires, approved_by and tracking")
			case record.Custody != "exception" && record.Exception != nil:
				// Otherwise an expired exception could be parked on a record whose custody says
				// hardware, where nothing would ever look at its date again.
				report.refuse(where, "an exception block is only meaningful with custody \"exception\", not %q", record.Custody)
			case record.Custody == "exception":
				// PRESENCE IS NOT AUDITABILITY. UnmarshalJSON refuses an exception that omits
				// approved_by or tracking, and until now that was the whole of the check -- so
				// `"approved_by": "x"` and `"tracking": "x"` satisfied every rule in the file.
				// The exception is the one record type that exists to be chased down and
				// re-argued, and a reference nobody can follow is the same dead end as no
				// reference. trackingPattern was written for this and then never applied, which
				// is why it sat in the file as an unused variable.
				checkField(&report, where, "exception.approved_by", record.Exception.ApprovedBy(), ownerPattern)
				checkField(&report, where, "exception.tracking", record.Exception.Tracking(), trackingPattern)
				// AN EXCEPTION PAST ITS EXPIRY. The type guarantees the date exists; only today can
				// say whether it has passed. Compared by day in UTC, matching
				// tools/custody_manifest.py, so an exception is live through the whole of its
				// final day rather than expiring at an hour nobody wrote down.
				today := time.Date(now.UTC().Year(), now.UTC().Month(), now.UTC().Day(), 0, 0, 0, 0, time.UTC)
				if record.Exception.Expires().Before(today) {
					report.refuse(where, "exception expired on %s: re-approve it or move the secret to a supported custody mode", record.Exception.Expires())
				}
			}
		}

		if len(report.Refusals) > before {
			report.Errored++
		}
	}

	// A SYSTEM DECLARED BUT NAMED BY NO RECORD. The other direction of the same rule, and the one
	// #33's fifth acceptance criterion is about: a system listed with an owner and no secrets reads
	// as "inventoried" in every count, while the actual discovery for it was never done. Silence
	// here is indistinguishable from a system that genuinely holds nothing, which is why it has to
	// be said out loud rather than inferred.
	for _, system := range document.Systems {
		if count, ok := declared[system.ID]; ok && count == 0 {
			report.refuse("systems "+system.ID, "declared but named by no record: either it holds no secrets and should say so, or its discovery is unfinished")
		}
	}

	// AN EMPTY INVENTORY MUST REFUSE, NOT PASS.
	//
	// A sibling tool in this repository exited 0 over a repository where it matched zero files and
	// printed a sentence asserting a property of files it had never opened. A verifier that accepts
	// an empty record set has the same defect in the same shape: it reports the estate clean by
	// having looked at none of it, and it is at its most convincing on the day someone points it at
	// the wrong path.
	if report.Records == 0 {
		report.refuse("document", "inventory declares no records: a run over an empty set is not a statement about the estate")
	} else if report.Errored == report.Records {
		// EVERY RECORD REFUSED IS ALSO NOT A RESULT. The run already fails on the individual
		// refusals, so this adds no failure today -- it names the condition, so that a later change
		// which downgrades per-record refusals to warnings cannot quietly turn a wholly unreadable
		// inventory back into a pass. It is the same defect as the empty set with the rows present.
		report.refuse("document", "all %d records were refused: this run verified nothing", report.Records)
	}
	return report
}
