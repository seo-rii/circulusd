package stateappclient

import (
	"bytes"
	"testing"
	"time"
)

func TestBrokerCredentialsAreDistinctOwnedAndCleared(t *testing.T) {
	base := Config{Endpoint: "http://127.0.0.1:1", KeyID: "read", RootKey: bytes.Repeat([]byte{1}, 32),
		DispatchStartKeyID: "dispatch", DispatchStartRootKey: bytes.Repeat([]byte{2}, 32),
		AdmissionKeyID: "admit", AdmissionRootKey: bytes.Repeat([]byte{3}, 32),
		BrokerKeyID: "broker", BrokerRootKey: bytes.Repeat([]byte{4}, 32), Timeout: time.Second}
	client, err := New(base)
	if err != nil {
		t.Fatal(err)
	}
	want := client.brokerRequestKey
	clear(base.BrokerRootKey)
	if want == ([32]byte{}) || client.brokerRequestKey != want {
		t.Fatal("broker keys were not snapshotted")
	}
	client.Close()
	if client.brokerRequestKey != ([32]byte{}) || client.brokerResponseKey != ([32]byte{}) {
		t.Fatal("closed client retained broker keys")
	}
	for _, role := range []struct {
		id  string
		key []byte
	}{{base.KeyID, base.RootKey}, {base.DispatchStartKeyID, base.DispatchStartRootKey}, {base.AdmissionKeyID, base.AdmissionRootKey}} {
		config := base
		config.BrokerRootKey = bytes.Repeat([]byte{4}, 32)
		config.BrokerKeyID = role.id
		if _, err := New(config); err == nil {
			t.Fatal("accepted duplicated broker key ID")
		}
		config.BrokerKeyID = "broker"
		config.BrokerRootKey = role.key
		if _, err := New(config); err == nil {
			t.Fatal("accepted duplicated broker key material")
		}
	}
	for _, config := range []Config{
		{Endpoint: base.Endpoint, KeyID: base.KeyID, RootKey: base.RootKey, BrokerKeyID: "broker", Timeout: time.Second},
		{Endpoint: base.Endpoint, KeyID: base.KeyID, RootKey: base.RootKey, BrokerRootKey: bytes.Repeat([]byte{4}, 32), Timeout: time.Second},
	} {
		if _, err := New(config); err == nil {
			t.Fatal("accepted half-configured broker credentials")
		}
	}
}
