package release

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"reflect"
	"sort"
)

var ErrArtifactVerification = errors.New("release artifact verification failed")

// ArtifactSource opens one immutable artifact from an offline bundle. The
// component and architecture are part of the lookup key so an `any` artifact
// cannot be confused with an architecture-specific artifact of the same name.
type ArtifactSource interface {
	OpenArtifact(
		context.Context,
		string,
		string,
		string,
	) (io.ReadCloser, error)
}

// VerifiedArtifact records the exact signed artifact bytes selected for an
// installation architecture.
type VerifiedArtifact struct {
	ComponentName string
	Architecture  string
	ArtifactName  string
	SHA256        string
	SizeBytes     uint64
}

type selectedArtifact struct {
	componentName string
	artifact      Artifact
}

type contextReader struct {
	ctx    context.Context
	reader io.Reader
}

func (reader contextReader) Read(buffer []byte) (int, error) {
	if err := reader.ctx.Err(); err != nil {
		return 0, err
	}
	return reader.reader.Read(buffer)
}

// VerifyArtifacts authenticates a promotable manifest and hashes every
// artifact applicable to architecture. It performs no installation mutation.
func (store *TrustStore) VerifyArtifacts(
	ctx context.Context,
	manifest Manifest,
	architecture string,
	source ArtifactSource,
) ([]VerifiedArtifact, error) {
	if ctx == nil {
		return nil, fmt.Errorf("%w: context is required", ErrArtifactVerification)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if source == nil {
		return nil, fmt.Errorf("%w: artifact source is required", ErrArtifactVerification)
	}
	sourceValue := reflect.ValueOf(source)
	switch sourceValue.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		if sourceValue.IsNil() {
			return nil, fmt.Errorf("%w: artifact source is required", ErrArtifactVerification)
		}
	}
	if err := store.VerifyPromotion(manifest); err != nil {
		return nil, fmt.Errorf("%w: authenticate manifest: %w", ErrArtifactVerification, err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if architecture != "x86_64" && architecture != "aarch64" {
		return nil, fmt.Errorf("%w: architecture %q is unsupported", ErrArtifactVerification, architecture)
	}
	releasedArchitecture := false
	for _, released := range manifest.Release.Architectures {
		if released == architecture {
			releasedArchitecture = true
			break
		}
	}
	if !releasedArchitecture {
		return nil, fmt.Errorf("%w: architecture %q is not present in the release", ErrArtifactVerification, architecture)
	}

	selected := make([]selectedArtifact, 0, len(manifest.Components))
	for _, component := range manifest.Components {
		componentArtifacts := 0
		for _, artifact := range component.Artifacts {
			if artifact.Architecture != "any" && artifact.Architecture != architecture {
				continue
			}
			componentArtifacts++
			selected = append(selected, selectedArtifact{componentName: component.Name, artifact: artifact})
		}
		if componentArtifacts == 0 {
			return nil, fmt.Errorf("%w: component %q has no artifact for %q", ErrArtifactVerification, component.Name, architecture)
		}
	}
	sort.Slice(selected, func(left, right int) bool {
		if selected[left].componentName != selected[right].componentName {
			return selected[left].componentName < selected[right].componentName
		}
		if selected[left].artifact.Architecture != selected[right].artifact.Architecture {
			return selected[left].artifact.Architecture < selected[right].artifact.Architecture
		}
		return selected[left].artifact.Name < selected[right].artifact.Name
	})

	verified := make([]VerifiedArtifact, 0, len(selected))
	buffer := make([]byte, 128<<10)
	for _, item := range selected {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if item.artifact.SizeBytes == nil || *item.artifact.SizeBytes == 0 {
			return nil, fmt.Errorf("%w: component %q artifact %q has no positive size", ErrArtifactVerification, item.componentName, item.artifact.Name)
		}
		artifactReader, err := source.OpenArtifact(
			ctx,
			item.componentName,
			item.artifact.Architecture,
			item.artifact.Name,
		)
		if err != nil {
			if ctxErr := ctx.Err(); ctxErr != nil {
				return nil, ctxErr
			}
			return nil, fmt.Errorf("%w: open component %q artifact %q: %w", ErrArtifactVerification, item.componentName, item.artifact.Name, err)
		}
		readerValue := reflect.ValueOf(artifactReader)
		nilReader := artifactReader == nil
		if !nilReader {
			switch readerValue.Kind() {
			case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
				nilReader = readerValue.IsNil()
			}
		}
		if nilReader {
			return nil, fmt.Errorf("%w: component %q artifact %q source returned nil", ErrArtifactVerification, item.componentName, item.artifact.Name)
		}

		expectedSize := *item.artifact.SizeBytes
		hasher := sha256.New()
		readBytes, readErr := io.CopyBuffer(
			hasher,
			io.LimitReader(contextReader{ctx: ctx, reader: artifactReader}, int64(expectedSize)+1),
			buffer,
		)
		closeErr := artifactReader.Close()
		if ctxErr := ctx.Err(); ctxErr != nil {
			return nil, ctxErr
		}
		if readErr != nil {
			return nil, fmt.Errorf("%w: read component %q artifact %q: %w", ErrArtifactVerification, item.componentName, item.artifact.Name, readErr)
		}
		if closeErr != nil {
			return nil, fmt.Errorf("%w: close component %q artifact %q: %w", ErrArtifactVerification, item.componentName, item.artifact.Name, closeErr)
		}
		if uint64(readBytes) != expectedSize {
			return nil, fmt.Errorf(
				"%w: component %q artifact %q size is %d, want %d",
				ErrArtifactVerification,
				item.componentName,
				item.artifact.Name,
				readBytes,
				expectedSize,
			)
		}
		actualDigest := hex.EncodeToString(hasher.Sum(nil))
		if actualDigest != item.artifact.SHA256 {
			return nil, fmt.Errorf("%w: component %q artifact %q SHA-256 mismatch", ErrArtifactVerification, item.componentName, item.artifact.Name)
		}
		verified = append(verified, VerifiedArtifact{
			ComponentName: item.componentName,
			Architecture:  item.artifact.Architecture,
			ArtifactName:  item.artifact.Name,
			SHA256:        actualDigest,
			SizeBytes:     expectedSize,
		})
	}
	return verified, nil
}
