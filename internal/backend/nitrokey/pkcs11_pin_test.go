package nitrokey

import (
	"os"
	"testing"
)

func e2ePKCS11PIN(t *testing.T) []byte {
	t.Helper()
	pin := os.Getenv("REGALIA_PKCS11_E2E_PIN")
	if pin == "" {
		t.Skip("set REGALIA_PKCS11_E2E_PIN")
	}
	return []byte(pin)
}
