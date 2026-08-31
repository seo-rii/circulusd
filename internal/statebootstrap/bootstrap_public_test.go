package statebootstrap_test

import (
	"reflect"
	"testing"

	"github.com/hancomac/circulusd/internal/statebootstrap"
)

func TestProductionGraphHasNoExportedCopyableConcreteRepresentation(t *testing.T) {
	t.Parallel()

	graphType := reflect.TypeOf((*statebootstrap.Graph)(nil)).Elem()
	if graphType.Kind() != reflect.Interface {
		t.Fatalf("statebootstrap.Graph kind = %v, want interface", graphType.Kind())
	}
}
