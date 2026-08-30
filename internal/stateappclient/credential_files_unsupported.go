//go:build !linux

package stateappclient

func loadRootKeyPair(_, _ string) ([]byte, []byte, error) {
	return nil, nil, ErrCredentialFilesUnsupported
}
