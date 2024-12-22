package auth

import (
	"net/http"
	"testing"
)

func TestGetRightAPIKey(t *testing.T) {
	realKey := "KEY123"
	header := http.Header{}
	header.Add("Authorization", "ApiKey "+realKey)

	getKey, err := GetAPIKey(header)
	if err != nil {
		t.Fatalf("error getting api key: %s", err)
	}

	if getKey != realKey {
		t.Fatalf("incorrect key")
	}
}

func TestGetWrongAPIKey(t *testing.T) {
	realKey := "KEY123"
	header := http.Header{}
	header.Add("Authorization", "ApiKey "+realKey+"4")

	getKey, err := GetAPIKey(header)
	if err != nil {
		t.Fatalf("error getting api key: %s", err)
	}

	if getKey == realKey {
		t.Fatalf("incorrect key")
	}
}

func TestGetWrongHeaderAPIKey(t *testing.T) {
	realKey := "KEY123"
	header := http.Header{}
	header.Add("Authorization", "ApiKeyyyy "+realKey)

	getKey, err := GetAPIKey(header)
	if err == nil {
		t.Fatalf("Should be error getting API key")
	}

	if getKey == realKey {
		t.Fatalf("got key with malformed header")
	}
}

func TestGetWrongHeaderAPIKey2(t *testing.T) {
	realKey := "KEY123"
	header := http.Header{}
	header.Add("Authorization2", "ApiKey "+realKey)

	getKey, err := GetAPIKey(header)
	if err == nil {
		t.Fatalf("Should be error getting API key")
	}

	if getKey == realKey {
		t.Fatalf("got key with malformed header")
	}
}
