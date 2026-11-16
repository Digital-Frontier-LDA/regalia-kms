package openbaopoc

import (
	"bytes"
	"encoding/json"
	"io"
)

// Responses are extensible under API v1. Ignore future fields, but never accept
// duplicate top-level keys or trailing documents that can alter interpretation.
func responseObject(data []byte) (map[string]json.RawMessage, error) {
	d := json.NewDecoder(bytes.NewReader(data))
	token, err := d.Token()
	if err != nil || token != json.Delim('{') {
		return nil, errOperation
	}
	fields := make(map[string]json.RawMessage)
	success := false
	defer func() {
		if !success {
			for _, v := range fields {
				clear(v)
			}
		}
	}()
	for d.More() {
		token, err = d.Token()
		key, ok := token.(string)
		if err != nil || !ok || fields[key] != nil {
			return nil, errOperation
		}
		var value json.RawMessage
		if d.Decode(&value) != nil {
			return nil, errOperation
		}
		fields[key] = value
	}
	if token, err = d.Token(); err != nil || token != json.Delim('}') {
		return nil, errOperation
	}
	var extra any
	if d.Decode(&extra) != io.EOF {
		return nil, errOperation
	}
	success = true
	return fields, nil
}

func decodeAPIResponse(data []byte, status int, id, object, contentType string, limit int) ([]byte, error) {
	protocol := &APIError{Code: "PROTOCOL_ERROR", RequestID: id}
	fields, err := responseObject(data)
	defer func() {
		for _, value := range fields {
			clear(value)
		}
	}()
	if err != nil {
		return nil, protocol
	}
	var responseID string
	if json.Unmarshal(fields["request_id"], &responseID) != nil || responseID != id {
		return nil, protocol
	}
	if status != 200 {
		var code string
		var retryable *bool
		if json.Unmarshal(fields["code"], &code) != nil || !apiCode.MatchString(code) ||
			json.Unmarshal(fields["retryable"], &retryable) != nil || retryable == nil || !errorStatus(code, status) {
			return nil, protocol
		}
		return nil, &APIError{Code: code, RequestID: id, Retryable: *retryable && retryCode(code)}
	}
	var operationID, responseObjectID, responseType string
	var result []byte
	if json.Unmarshal(fields["operation_id"], &operationID) != nil || operationID == "" ||
		json.Unmarshal(fields["object_id"], &responseObjectID) != nil || responseObjectID != object ||
		json.Unmarshal(fields["content_type"], &responseType) != nil || responseType != contentType ||
		json.Unmarshal(fields["result_base64"], &result) != nil || len(result) == 0 || len(result) > limit {
		clear(result)
		return nil, protocol
	}
	return result, nil
}
