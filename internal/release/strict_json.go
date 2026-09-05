package release

import (
	"fmt"

	"github.com/hancomac/circulusd/internal/strictjson"
)

func decodeStrictJSON(encoded []byte, label string, destination any) error {
	if err := strictjson.Decode(encoded, destination); err != nil {
		return fmt.Errorf("decode %s: %w", label, err)
	}
	return nil
}
