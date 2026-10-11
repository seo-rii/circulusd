package stateappclient

import (
	"bytes"
	"errors"
	"fmt"
	"time"
)

var (
	ErrInvalidCredentialFile      = errors.New("state app client: invalid credential file")
	ErrCredentialFilesUnsupported = errors.New("state app client: credential files are unsupported on this platform")
)

// CredentialFileConfig names the operation-scoped root-key files used to
// construct a state-app client. The files are snapshotted exactly once during
// construction; request processing never reopens them.
type CredentialFileConfig struct {
	BrokerKeyID              string
	BrokerRootKeyFile        string
	AdmissionKeyID           string
	AdmissionRootKeyFile     string
	Endpoint                 string
	KeyID                    string
	RootKeyFile              string
	DispatchStartKeyID       string
	DispatchStartRootKeyFile string
	Timeout                  time.Duration
}

// NewFromCredentialFiles constructs a client from service-owned credential
// files. It clears all decoded loader buffers after New has derived and copied
// the operation-specific client keys.
func NewFromCredentialFiles(config CredentialFileConfig) (*Client, error) {
	return newFromCredentialFiles(config, New)
}

func newFromCredentialFiles(config CredentialFileConfig, constructor func(Config) (*Client, error)) (*Client, error) {
	if config.RootKeyFile == "" || config.DispatchStartRootKeyFile == "" ||
		config.RootKeyFile == config.DispatchStartRootKeyFile {
		return nil, ErrInvalidCredentialFile
	}
	paths := []string{config.RootKeyFile, config.DispatchStartRootKeyFile}
	admissionConfigured := config.AdmissionKeyID != "" || config.AdmissionRootKeyFile != ""
	if admissionConfigured {
		if config.AdmissionKeyID == "" || config.AdmissionRootKeyFile == "" ||
			config.AdmissionRootKeyFile == config.RootKeyFile || config.AdmissionRootKeyFile == config.DispatchStartRootKeyFile {
			return nil, ErrInvalidCredentialFile
		}
		paths = append(paths, config.AdmissionRootKeyFile)
	}
	brokerConfigured := config.BrokerKeyID != "" || config.BrokerRootKeyFile != ""
	brokerIndex := len(paths)
	if brokerConfigured {
		if config.BrokerKeyID == "" || config.BrokerRootKeyFile == "" {
			return nil, ErrInvalidCredentialFile
		}
		for _, path := range paths {
			if config.BrokerRootKeyFile == path {
				return nil, ErrInvalidCredentialFile
			}
		}
		paths = append(paths, config.BrokerRootKeyFile)
	}
	keys, err := loadRootKeyFiles(paths...)
	if err != nil {
		return nil, err
	}
	defer func() {
		for _, key := range keys {
			clear(key)
		}
	}()
	for i, key := range keys {
		for _, prior := range keys[:i] {
			if bytes.Equal(key, prior) {
				return nil, fmt.Errorf("%w: operation roles must use distinct key material", ErrInvalidCredentialFile)
			}
		}
	}
	var admissionKey []byte
	if admissionConfigured {
		admissionKey = keys[2]
	}
	var brokerKey []byte
	if brokerConfigured {
		brokerKey = keys[brokerIndex]
	}
	return constructor(Config{
		Endpoint: config.Endpoint, KeyID: config.KeyID, RootKey: keys[0],
		DispatchStartKeyID: config.DispatchStartKeyID, DispatchStartRootKey: keys[1],
		AdmissionKeyID: config.AdmissionKeyID, AdmissionRootKey: admissionKey, Timeout: config.Timeout,
		BrokerKeyID: config.BrokerKeyID, BrokerRootKey: brokerKey,
	})
}
