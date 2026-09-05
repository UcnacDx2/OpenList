package _139

import (
	"testing"
	"time"
)

func TestRefreshTokenUsesAuthorizationRenewalImplementation(t *testing.T) {
	oldAuthorization := makeAuthorization("18800000000", makeToken(time.Now().Add(authorizationRenewWindow+time.Hour), "entry"))
	d := Yun139{Addition: Addition{Authorization: oldAuthorization}}
	if err := d.refreshToken(); err != nil {
		t.Fatalf("refreshToken() error = %v", err)
	}
	if d.Authorization != oldAuthorization {
		t.Fatal("refreshToken() unexpectedly changed an authorization outside the renewal window")
	}
	if d.Account != "18800000000" {
		t.Fatalf("Account = %q, want parsed account", d.Account)
	}
}

func TestRefreshTokenDelegatesReferenceThroughStableEntry(t *testing.T) {
	oldAuthorization := makeAuthorization("18800000001", makeToken(time.Now().Add(authorizationRenewWindow+time.Hour), "reference"))
	ref := &Yun139{Addition: Addition{Authorization: oldAuthorization}}
	d := Yun139{ref: ref}
	if err := d.refreshToken(); err != nil {
		t.Fatalf("refreshToken() reference error = %v", err)
	}
	if ref.Account != "18800000001" {
		t.Fatalf("reference Account = %q, want parsed account", ref.Account)
	}
}
