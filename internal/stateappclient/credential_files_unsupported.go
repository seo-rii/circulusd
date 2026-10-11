//go:build !linux

package stateappclient

func loadRootKeyFiles(_ ...string) ([][]byte, error) { return nil, ErrCredentialFilesUnsupported }
