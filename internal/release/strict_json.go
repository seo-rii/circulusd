package release

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
)

type jsonContainer struct {
	kind         json.Delim
	keys         map[string]struct{}
	expectingKey bool
}

func decodeStrictJSON(encoded []byte, label string, destination any) error {
	tokenDecoder := json.NewDecoder(bytes.NewReader(encoded))
	tokenDecoder.UseNumber()
	containers := make([]jsonContainer, 0, 8)
	completeValue := func() {
		if len(containers) == 0 {
			return
		}
		current := &containers[len(containers)-1]
		if current.kind == '{' && !current.expectingKey {
			current.expectingKey = true
		}
	}
	for {
		token, err := tokenDecoder.Token()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("decode %s: %w", label, err)
		}
		if delimiter, ok := token.(json.Delim); ok {
			switch delimiter {
			case '{':
				containers = append(containers, jsonContainer{
					kind:         delimiter,
					keys:         make(map[string]struct{}),
					expectingKey: true,
				})
			case '[':
				containers = append(containers, jsonContainer{kind: delimiter})
			case '}', ']':
				if len(containers) == 0 || containers[len(containers)-1].kind+2 != delimiter {
					return fmt.Errorf("decode %s: mismatched JSON container", label)
				}
				containers = containers[:len(containers)-1]
				completeValue()
			}
			continue
		}
		if len(containers) > 0 {
			current := &containers[len(containers)-1]
			if current.kind == '{' && current.expectingKey {
				key, ok := token.(string)
				if !ok {
					return fmt.Errorf("decode %s: JSON object key is not a string", label)
				}
				if _, duplicate := current.keys[key]; duplicate {
					return fmt.Errorf("decode %s: duplicate JSON member %q", label, key)
				}
				current.keys[key] = struct{}{}
				current.expectingKey = false
				continue
			}
		}
		completeValue()
	}
	if len(containers) != 0 {
		return fmt.Errorf("decode %s: incomplete JSON container", label)
	}

	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(destination); err != nil {
		return fmt.Errorf("decode %s: %w", label, err)
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		if err == nil {
			return fmt.Errorf("decode %s: trailing JSON value", label)
		}
		return fmt.Errorf("decode %s trailer: %w", label, err)
	}
	return nil
}
