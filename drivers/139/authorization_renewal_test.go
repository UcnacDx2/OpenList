package _139

import (
	"crypto/aes"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/go-resty/resty/v2"
)

func makeAuthorization(account, token string) string {
	return base64.StdEncoding.EncodeToString([]byte("pc:" + account + ":" + token))
}

func makeToken(expiry time.Time, prefix string) string {
	return fmt.Sprintf("%s|scope|session|%d", prefix, expiry.UnixMilli())
}

func TestParseYun139Authorization(t *testing.T) {
	expiresAt := time.UnixMilli(1893456000000)
	raw := makeAuthorization("18800000000", makeToken(expiresAt, "token"))

	got, err := parseYun139Authorization(raw)
	if err != nil {
		t.Fatalf("parseYun139Authorization() error = %v", err)
	}
	if got.Account != "18800000000" {
		t.Fatalf("Account = %q", got.Account)
	}
	if got.Token != makeToken(expiresAt, "token") {
		t.Fatalf("Token = %q", got.Token)
	}
	if !got.ExpiresAt.Equal(expiresAt) {
		t.Fatalf("ExpiresAt = %v, want %v", got.ExpiresAt, expiresAt)
	}
}

func TestShouldRenewAuthorizationAtThreeDayBoundary(t *testing.T) {
	now := time.Date(2026, 9, 5, 12, 0, 0, 0, time.UTC)
	if shouldRenewAuthorization(now.Add(authorizationRenewWindow+time.Second), now) {
		t.Fatal("authorization outside the 72-hour window should not renew")
	}
	if !shouldRenewAuthorization(now.Add(authorizationRenewWindow), now) {
		t.Fatal("authorization at the 72-hour boundary should renew")
	}
	if !shouldRenewAuthorization(now.Add(24*time.Hour), now) {
		t.Fatal("authorization inside the 72-hour window should renew")
	}
}

func TestRefreshAuthorizationSkipsNetworkBeforeRenewWindow(t *testing.T) {
	oldClient := base.RestyClient
	base.RestyClient = resty.New().SetTransport(roundTripFunc(func(*http.Request) (*http.Response, error) {
		t.Fatal("refreshAuthorization() made a network request before the renewal window")
		return nil, nil
	}))
	defer func() { base.RestyClient = oldClient }()

	oldAuthorization := makeAuthorization("18800000000", makeToken(time.Now().Add(authorizationRenewWindow+time.Hour), "old"))
	d := Yun139{Addition: Addition{Authorization: oldAuthorization}}
	if err := d.refreshAuthorization(); err != nil {
		t.Fatalf("refreshAuthorization() error = %v", err)
	}
	if d.Authorization != oldAuthorization {
		t.Fatalf("Authorization changed before renewal window")
	}
	if d.Account != "18800000000" {
		t.Fatalf("Account = %q, want parsed account", d.Account)
	}
}

func TestRenewAuthorizationViaMailEndToEnd(t *testing.T) {
	const account = "18800000000"
	now := time.Now()
	oldAuthorization := makeAuthorization(account, makeToken(now.Add(48*time.Hour), "old-auth"))
	newToken := makeToken(now.Add(30*24*time.Hour), "new-auth")

	var ticketCalls, mailCalls, artifactCalls, thirdCalls int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, err := io.ReadAll(r.Body)
		if err != nil {
			t.Fatalf("read request body: %v", err)
		}

		switch r.URL.Path {
		case "/ticket":
			ticketCalls++
			if r.Header.Get("Authorization") != "Basic "+oldAuthorization {
				t.Errorf("ticket Authorization = %q", r.Header.Get("Authorization"))
			}
			if !strings.Contains(string(body), "<toSourceId>001003</toSourceId>") || !strings.Contains(string(body), "<account>"+account+"</account>") {
				t.Errorf("ticket body = %s", body)
			}
			w.Header().Set("Content-Type", "application/xml")
			_, _ = io.WriteString(w, `<root><return>0</return><token>YZsidssolg-test-ticket</token></root>`)

		case "/mail":
			mailCalls++
			if !strings.Contains(string(body), `<string name="loginType">7</string>`) {
				t.Errorf("mail body missing loginType=7: %s", body)
			}
			if !strings.Contains(string(body), `<string name="token">YZsidssolg-test-ticket</string>`) {
				t.Errorf("mail body missing cloud ticket: %s", body)
			}
			http.SetCookie(w, &http.Cookie{Name: "mailTheme", Value: "blue"})
			w.Header().Set("Content-Type", "application/json")
			_, _ = io.WriteString(w, `{"code":"S_OK","var":{"sid":"mail-sid","rmkey":"mail-rmkey"}}`)

		case "/artifact":
			artifactCalls++
			if r.URL.Query().Get("func") != "umc:getArtifact" {
				t.Errorf("artifact func = %q", r.URL.Query().Get("func"))
			}
			if r.URL.Query().Get("sid") != "mail-sid" {
				t.Errorf("artifact sid = %q", r.URL.Query().Get("sid"))
			}
			if r.Header.Get("Cookie") != "RMKEY=mail-rmkey" {
				t.Errorf("artifact Cookie = %q", r.Header.Get("Cookie"))
			}
			_, _ = io.WriteString(w, `{"var":{"artifact":"renew-artifact"}}`)

		case "/third":
			thirdCalls++
			if len(body) == 0 {
				t.Error("thirdlogin encrypted body is empty")
			}
			finalJSON := fmt.Sprintf(`{"account":"%s","authToken":"%s","userDomainId":"domain-1"}`, account, newToken)
			layer2 := testEncryptECB([]byte(finalJSON), mustDecodeHex(t, KEY_HEX_2))
			layer1JSON := []byte(fmt.Sprintf(`{"data":"%s"}`, hex.EncodeToString(layer2)))
			key1 := mustDecodeHex(t, KEY_HEX_1)
			iv := []byte("0123456789abcdef")
			layer1, err := aesCbcEncrypt(layer1JSON, key1, iv)
			if err != nil {
				t.Fatalf("encrypt layer1: %v", err)
			}
			w.Header().Set("Content-Type", "text/plain")
			_, _ = io.WriteString(w, base64.StdEncoding.EncodeToString(append(iv, layer1...)))

		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	oldTicketURL := driveMailTicketURL
	oldMailURL := driveMailLoginURL
	oldArtifactURL := driveRenewArtifactURL
	oldThirdURL := driveRenewThirdLoginURL
	driveMailTicketURL = server.URL + "/ticket"
	driveMailLoginURL = server.URL + "/mail"
	driveRenewArtifactURL = server.URL + "/artifact"
	driveRenewThirdLoginURL = server.URL + "/third"
	defer func() {
		driveMailTicketURL = oldTicketURL
		driveMailLoginURL = oldMailURL
		driveRenewArtifactURL = oldArtifactURL
		driveRenewThirdLoginURL = oldThirdURL
	}()

	oldClient := base.RestyClient
	base.RestyClient = resty.New().SetRetryCount(0)
	defer func() { base.RestyClient = oldClient }()

	info, err := parseYun139Authorization(oldAuthorization)
	if err != nil {
		t.Fatalf("parse old authorization: %v", err)
	}
	d := Yun139{Addition: Addition{Authorization: oldAuthorization}}
	result, err := d.renewAuthorizationViaMail(info)
	if err != nil {
		t.Fatalf("renewAuthorizationViaMail() error = %v", err)
	}

	if ticketCalls != 1 || mailCalls != 1 || artifactCalls != 1 || thirdCalls != 1 {
		t.Fatalf("calls ticket/mail/artifact/third = %d/%d/%d/%d, want 1/1/1/1", ticketCalls, mailCalls, artifactCalls, thirdCalls)
	}
	if result.Authorization == oldAuthorization || result.Authorization == "" {
		t.Fatalf("Authorization was not renewed")
	}
	newInfo, err := parseYun139Authorization(result.Authorization)
	if err != nil {
		t.Fatalf("parse renewed authorization: %v", err)
	}
	if newInfo.Account != account || newInfo.Token != newToken {
		t.Fatalf("renewed authorization = account %q token %q", newInfo.Account, newInfo.Token)
	}
	if result.UserDomainID != "domain-1" {
		t.Fatalf("UserDomainID = %q", result.UserDomainID)
	}
	for _, want := range []string{"Os_SSo_Sid=mail-sid", "sid=mail-sid", "RMKEY=mail-rmkey", "mailTheme=blue"} {
		if !strings.Contains(result.MailCookies, want) {
			t.Fatalf("MailCookies = %q, missing %q", result.MailCookies, want)
		}
	}
}

func TestRecoverMailSessionRejectsTicketFailure(t *testing.T) {
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = io.WriteString(w, `<root><return>1</return><desc>expired</desc></root>`)
	}))
	defer server.Close()

	oldTicketURL := driveMailTicketURL
	driveMailTicketURL = server.URL
	defer func() { driveMailTicketURL = oldTicketURL }()

	oldClient := base.RestyClient
	base.RestyClient = resty.New().SetRetryCount(0)
	defer func() { base.RestyClient = oldClient }()

	info := yun139AuthorizationInfo{
		Account:   "18800000000",
		Token:     makeToken(time.Now().Add(time.Hour), "old"),
		ExpiresAt: time.Now().Add(time.Hour),
	}
	d := Yun139{}
	_, err := d.recoverMailSessionFromAuthorization(info)
	if err == nil || !strings.Contains(err.Error(), "could not obtain mail ticket") {
		t.Fatalf("recoverMailSessionFromAuthorization() error = %v", err)
	}
}

type roundTripFunc func(*http.Request) (*http.Response, error)

func (f roundTripFunc) RoundTrip(r *http.Request) (*http.Response, error) {
	return f(r)
}

func mustDecodeHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, err := hex.DecodeString(value)
	if err != nil {
		t.Fatalf("decode hex: %v", err)
	}
	return decoded
}

func testEncryptECB(plain, key []byte) []byte {
	block, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	padded := pkcs7_pad(plain, block.BlockSize())
	out := make([]byte, len(padded))
	for start := 0; start < len(padded); start += block.BlockSize() {
		block.Encrypt(out[start:start+block.BlockSize()], padded[start:start+block.BlockSize()])
	}
	return out
}
