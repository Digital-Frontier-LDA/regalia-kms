package server

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type probeFunc func(context.Context) bool

func (fn probeFunc) Ready(ctx context.Context) bool { return fn(ctx) }

func request(t *testing.T, handler http.Handler, method, path string) *httptest.ResponseRecorder {
	t.Helper()
	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(method, path, nil))
	return recorder
}

func decodeStatus(t *testing.T, recorder *httptest.ResponseRecorder) map[string]any {
	t.Helper()
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatalf("decode health response: %v", err)
	}
	return payload
}

func TestLivenessReturnsOnlyOKStatus(t *testing.T) {
	handler := New(nil)
	recorder := request(t, handler, http.MethodGet, "/v1/health/live")

	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200", recorder.Code)
	}
	payload := decodeStatus(t, recorder)
	if len(payload) != 1 || payload["status"] != "ok" {
		t.Fatalf("payload = %#v, want only status=ok", payload)
	}
	if got := recorder.Header().Get("Cache-Control"); got != "no-store" {
		t.Fatalf("Cache-Control = %q, want no-store", got)
	}
}

func TestReadinessFailsClosedWhenNoProbesExist(t *testing.T) {
	handler := New(nil)
	recorder := request(t, handler, http.MethodGet, "/v1/health/ready")

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	payload := decodeStatus(t, recorder)
	if len(payload) != 1 || payload["status"] != "unavailable" {
		t.Fatalf("payload = %#v, want only status=unavailable", payload)
	}
}

func TestReadinessRequiresEveryProbe(t *testing.T) {
	tests := []struct {
		name   string
		probes []ReadinessProbe
		status int
	}{
		{"all ready", []ReadinessProbe{probeFunc(func(context.Context) bool { return true }), probeFunc(func(context.Context) bool { return true })}, http.StatusOK},
		{"one unavailable", []ReadinessProbe{probeFunc(func(context.Context) bool { return true }), probeFunc(func(context.Context) bool { return false })}, http.StatusServiceUnavailable},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			recorder := request(t, New(test.probes), http.MethodGet, "/v1/health/ready")
			if recorder.Code != test.status {
				t.Fatalf("status = %d, want %d", recorder.Code, test.status)
			}
		})
	}
}

func TestReadinessProbePanicFailsClosedWithoutDetail(t *testing.T) {
	handler := New([]ReadinessProbe{probeFunc(func(context.Context) bool { panic("sensitive probe failure") })})
	recorder := request(t, handler, http.MethodGet, "/v1/health/ready")

	if recorder.Code != http.StatusServiceUnavailable {
		t.Fatalf("status = %d, want 503", recorder.Code)
	}
	if payload := decodeStatus(t, recorder); len(payload) != 1 || payload["status"] != "unavailable" {
		t.Fatalf("payload = %#v, want only status=unavailable", payload)
	}
	if body := recorder.Body.String(); body == "" || body == "sensitive probe failure" {
		t.Fatalf("unsafe body = %q", body)
	}
}

func TestHealthRejectsWrongMethodWithoutDetail(t *testing.T) {
	recorder := request(t, New(nil), http.MethodPost, "/v1/health/live")
	if recorder.Code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 405", recorder.Code)
	}
	if recorder.Body.String() != "" {
		t.Fatalf("body = %q, want empty", recorder.Body.String())
	}
}

func TestUnknownPathUsesEmptyNotFoundResponse(t *testing.T) {
	recorder := request(t, New(nil), http.MethodGet, "/debug/config")
	if recorder.Code != http.StatusNotFound {
		t.Fatalf("status = %d, want 404", recorder.Code)
	}
	if recorder.Body.String() != "" {
		t.Fatalf("body = %q, want empty", recorder.Body.String())
	}
}

func TestRoutesHealthAndOperationsWithoutExposingOtherPaths(t *testing.T) {
	operations := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusTeapot)
	})
	handler := Routes(New(nil), operations, New(nil), nil)
	if got := request(t, handler, http.MethodGet, "/v1/health/live").Code; got != http.StatusOK {
		t.Fatalf("health status = %d", got)
	}
	if got := request(t, handler, http.MethodPost, "/v1/operations/unwrap").Code; got != http.StatusTeapot {
		t.Fatalf("operation status = %d", got)
	}
	if got := request(t, handler, http.MethodGet, "/debug/config").Code; got != http.StatusNotFound {
		t.Fatalf("unknown status = %d", got)
	}
}
