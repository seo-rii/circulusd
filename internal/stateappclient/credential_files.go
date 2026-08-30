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

// CredentialFileConfig names the two operation-scoped root-key files used to
// construct a state-app client. The files are snapshotted exactly once during
// construction; request processing never reopens them.
type CredentialFileConfig struct {
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
	readRootKey, dispatchStartRootKey, err := loadRootKeyPair(
		config.RootKeyFile,
		config.DispatchStartRootKeyFile,
	)
	if err != nil {
		return nil, err
	}
	defer clear(readRootKey)
	defer clear(dispatchStartRootKey)
	if bytes.Equal(readRootKey, dispatchStartRootKey) {
		return nil, fmt.Errorf("%w: read and dispatch-start authority must use distinct key material", ErrInvalidCredentialFile)
	}
	return constructor(Config{
		Endpoint:             config.Endpoint,
		KeyID:                config.KeyID,
		RootKey:              readRootKey,
		DispatchStartKeyID:   config.DispatchStartKeyID,
		DispatchStartRootKey: dispatchStartRootKey,
		Timeout:              config.Timeout,
	})
}
