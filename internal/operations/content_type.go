package operations

// DataKeyContentType is the content type the coordinator evaluates a release-secret or seal-envelope
// under. Those requests cannot carry one (the API refuses a content_type on them), so a purpose policy
// for either operation must list THIS type, or every such request is denied "content".
const DataKeyContentType = "application/vnd.regalia.data-key"
