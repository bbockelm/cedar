package security

import (
	"crypto/rand"
	"testing"
	"time"

	"github.com/jcmturner/gokrb5/v8/iana/etypeID"
	"github.com/jcmturner/gokrb5/v8/iana/nametype"
	"github.com/jcmturner/gokrb5/v8/types"
)

// buildTestAPRep produces a wire AP_REP echoing (ctime, cusec) via the same
// server-side builder used in production, so the test exercises the real
// server-AP_REP → client-validate round trip.
func buildTestAPRep(t *testing.T, key types.EncryptionKey, ctime time.Time, cusec int) []byte {
	t.Helper()
	b, err := buildKerberosAPRep(ctime, cusec, key)
	if err != nil {
		t.Fatalf("buildKerberosAPRep: %v", err)
	}
	return b
}

func testSessionKey(t *testing.T) types.EncryptionKey {
	t.Helper()
	kv := make([]byte, 32) // aes256
	if _, err := rand.Read(kv); err != nil {
		t.Fatal(err)
	}
	return types.EncryptionKey{KeyType: etypeID.AES256_CTS_HMAC_SHA1_96, KeyValue: kv}
}

func TestValidateKerberosAPRep(t *testing.T) {
	key := testSessionKey(t)
	sent, err := types.NewAuthenticator("EXAMPLE.ORG",
		types.NewPrincipalName(nametype.KRB_NT_PRINCIPAL, "alice"))
	if err != nil {
		t.Fatal(err)
	}

	t.Run("valid", func(t *testing.T) {
		ok := buildTestAPRep(t, key, sent.CTime, sent.Cusec)
		if err := validateKerberosAPRep(ok, key, sent); err != nil {
			t.Errorf("valid AP_REP rejected: %v", err)
		}
	})

	t.Run("wrong timestamp", func(t *testing.T) {
		bad := buildTestAPRep(t, key, sent.CTime.Add(time.Second), sent.Cusec)
		if err := validateKerberosAPRep(bad, key, sent); err == nil {
			t.Error("AP_REP with mismatched ctime was accepted")
		}
	})

	t.Run("wrong cusec", func(t *testing.T) {
		bad := buildTestAPRep(t, key, sent.CTime, sent.Cusec+1)
		if err := validateKerberosAPRep(bad, key, sent); err == nil {
			t.Error("AP_REP with mismatched cusec was accepted")
		}
	})

	t.Run("wrong key", func(t *testing.T) {
		ok := buildTestAPRep(t, key, sent.CTime, sent.Cusec)
		if err := validateKerberosAPRep(ok, testSessionKey(t), sent); err == nil {
			t.Error("AP_REP decrypted under the wrong key was accepted")
		}
	})

	t.Run("garbage", func(t *testing.T) {
		if err := validateKerberosAPRep([]byte{0x00, 0x01, 0x02}, key, sent); err == nil {
			t.Error("garbage AP_REP was accepted")
		}
	})
}
