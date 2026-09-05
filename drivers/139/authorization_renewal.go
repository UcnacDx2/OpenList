package _139

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	cookiepkg "github.com/OpenListTeam/OpenList/v4/pkg/cookie"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils/random"
	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
)

const authorizationRenewWindow = 72 * time.Hour

var (
	driveMailTicketURL      = "https://aas.caiyun.feixin.10086.cn/tellin/querySpecToken.do"
	driveMailLoginURL       = "https://mail.10086.cn/login/inlogin.action"
	driveRenewArtifactURL   = "https://smsrebuild1.mail.10086.cn/setting/s"
	driveRenewThirdLoginURL = "https://user-njs.yun.139.com/user/thirdlogin"
)

type yun139AuthorizationInfo struct {
	Account   string
	Token     string
	ExpiresAt time.Time
}

type authorizationRenewalResult struct {
	Authorization string
	MailCookies   string
	Account       string
	UserDomainID  string
}

func parseYun139Authorization(raw string) (yun139AuthorizationInfo, error) {
	decoded, err := base64.StdEncoding.DecodeString(strings.TrimSpace(raw))
	if err != nil {
		return yun139AuthorizationInfo{}, fmt.Errorf("authorization decode failed: %w", err)
	}
	parts := strings.SplitN(string(decoded), ":", 3)
	if len(parts) != 3 || strings.TrimSpace(parts[1]) == "" || strings.TrimSpace(parts[2]) == "" {
		return yun139AuthorizationInfo{}, errors.New("authorization is invalid")
	}

	tokenParts := strings.Split(parts[2], "|")
	if len(tokenParts) < 4 {
		return yun139AuthorizationInfo{}, errors.New("authorization token does not contain an expiration time")
	}
	expiresAtMillis, err := strconv.ParseInt(tokenParts[3], 10, 64)
	if err != nil || expiresAtMillis <= 0 {
		return yun139AuthorizationInfo{}, errors.New("authorization expiration is invalid")
	}

	return yun139AuthorizationInfo{
		Account:   strings.TrimSpace(parts[1]),
		Token:     parts[2],
		ExpiresAt: time.UnixMilli(expiresAtMillis),
	}, nil
}

func shouldRenewAuthorization(expiresAt, now time.Time) bool {
	return !expiresAt.After(now.Add(authorizationRenewWindow))
}

// refreshAuthorization keeps Authorization as the primary credential. A valid
// Authorization is left untouched until it enters the last 72 hours of its
// lifetime. Inside that window, the driver uses the current cloud credential to
// recover a fresh 139 Mail session, then performs the existing mail fast-login
// exchange to obtain a new cloud Authorization.
func (d *Yun139) refreshAuthorization() error {
	info, err := parseYun139Authorization(d.Authorization)
	if err != nil {
		return d.loginAfterAuthorizationFailure(err)
	}
	d.Account = info.Account

	now := time.Now()
	if info.ExpiresAt.After(now.Add(authorizationRenewWindow)) {
		return nil
	}
	if !info.ExpiresAt.After(now) {
		return d.loginAfterAuthorizationFailure(errors.New("authorization has expired"))
	}

	result, err := d.renewAuthorizationViaMail(info)
	if err != nil {
		// Keep the still-valid Authorization usable. Init and the normal request
		// path must not be broken by a transient renewal failure; the 12-hour
		// cron will retry while the credential is still inside the renewal window.
		log.Warnf("139yun: authorization expires within 72 hours, mail-session renewal failed; keeping current authorization for retry: %v", err)
		return nil
	}

	d.Authorization = result.Authorization
	d.MailCookies = result.MailCookies
	d.Account = result.Account
	d.UserDomainID = result.UserDomainID
	op.MustSaveDriverStorage(d)
	log.Infof("139yun: authorization renewed through cloud -> mail -> fast-login flow.")
	return nil
}

func (d *Yun139) renewAuthorizationViaMail(info yun139AuthorizationInfo) (authorizationRenewalResult, error) {
	mailCookies, err := d.recoverMailSessionFromAuthorization(info)
	if err != nil {
		return authorizationRenewalResult{}, err
	}

	sid, rmkey := extractFastLoginCookies(mailCookies)
	if sid == "" || rmkey == "" {
		return authorizationRenewalResult{}, errors.New("recovered mail session is missing sid or RMKEY")
	}

	artifact, err := d.renewalStep2GetArtifact(sid, rmkey)
	if err != nil {
		return authorizationRenewalResult{}, err
	}

	authorization, userDomainID, err := d.renewalStep3ThirdPartyLogin(info.Account, artifact)
	if err != nil {
		return authorizationRenewalResult{}, err
	}

	return authorizationRenewalResult{
		Authorization: authorization,
		MailCookies:   mailCookies,
		Account:       info.Account,
		UserDomainID:  userDomainID,
	}, nil
}

type driveMailTicketResponse struct {
	Return string `xml:"return"`
	Code   string `xml:"code"`
	Token  string `xml:"token"`
	Desc   string `xml:"desc"`
}

type driveMailLoginResponse struct {
	Code    string `json:"code"`
	Summary string `json:"summary"`
	Var     struct {
		LoginSuccessURL string `json:"loginSuccessUrl"`
		SID             string `json:"sid"`
		RMKEY           string `json:"rmkey"`
	} `json:"var"`
}

func authorizationDeviceInfo() string {
	// Match the mobile-cloud client shape used by the working reverse exchange.
	// OpenList does not currently persist a per-storage mobile device profile, so
	// keep this identity stable rather than generating a new device every retry.
	return "1|127.0.0.1|1|12.3.2|Xiaomi|23116PN5BC||02-00-00-00-00-00|android 15|1220X2574|zh||||108|"
}

func (d *Yun139) recoverMailSessionFromAuthorization(info yun139AuthorizationInfo) (string, error) {
	deviceInfo := authorizationDeviceInfo()
	pcAuthorization := base64.StdEncoding.EncodeToString([]byte("pc:" + info.Account + ":" + info.Token))
	ticketBody := "<root><account>" + escapeXML(info.Account) + "</account><toSourceId>001003</toSourceId></root>"

	ticketResp, err := new139RestyClient().SetRetryCount(0).R().
		SetHeaders(map[string]string{
			"x-nettype":           "1",
			"x-deviceinfo":        deviceInfo,
			"x-yun-client-info":   deviceInfo,
			"x-yun-app-channel":   "10000023",
			"x-huawei-channelsrc": "10000023",
			"x-mm-source":         "108",
			"x-svctype":           "1",
			"app_number":          info.Account,
			"x-exproute-code":     "routeCode=" + info.Account + ",type=10",
			"authorization":       "Basic " + pcAuthorization,
			"content-type":        "application/xml; charset=UTF-8",
			"user-agent":          "okhttp/3.11.0",
		}).
		SetBody(ticketBody).
		Post(driveMailTicketURL)
	if err != nil {
		return "", fmt.Errorf("query mail ticket from cloud authorization: %w", err)
	}
	if ticketResp.StatusCode() < http.StatusOK || ticketResp.StatusCode() >= http.StatusMultipleChoices {
		return "", fmt.Errorf("query mail ticket returned HTTP %d", ticketResp.StatusCode())
	}

	var ticket driveMailTicketResponse
	if err := xml.Unmarshal(ticketResp.Body(), &ticket); err != nil {
		return "", fmt.Errorf("parse mail ticket response: %w", err)
	}
	ticket.Token = strings.TrimSpace(ticket.Token)
	if ticket.Token == "" {
		code := strings.TrimSpace(ticket.Return)
		if code == "" {
			code = strings.TrimSpace(ticket.Code)
		}
		return "", fmt.Errorf("cloud authorization could not obtain mail ticket: code=%s desc=%s", code, strings.TrimSpace(ticket.Desc))
	}

	cguid := strconv.FormatInt(time.Now().UnixMilli(), 10) + random.String(12)
	loginBody := strings.Join([]string{
		"<object>",
		mailXMLField("clientid", "10891"),
		mailXMLField("version", "66"),
		mailXMLField("loginType", "7"),
		mailXMLField("autoSecretKey", ""),
		mailXMLField("createAutoLoginSecretKey", "1"),
		mailXMLField("verifyCode", `""`),
		mailXMLField("authType", "2"),
		mailXMLField("needWCookie", "1"),
		mailXMLField("verifyAgentId", ""),
		mailXMLField("loginName", ""),
		mailXMLField("loginPassword", ""),
		mailXMLField("loginToken", ""),
		mailXMLField("token", ticket.Token),
		mailXMLField("logActionId", ""),
		`<int name="eMode">1</int>`,
		"</object>",
	}, "")
	loginURL := driveMailLoginURL + "?comefrom=2066&clientId=10891&cguid=" + url.QueryEscape(cguid) + "&deviceToken=ZFHIXQJV8EDNJO6H3D9M77WEQG2NO6TQ&appVersion=8.0.28"
	loginResp, err := new139RestyClient().SetRetryCount(0).R().
		SetHeaders(map[string]string{
			"content-type": "application/xml",
			"user-agent":   "Mozilla/5.0 (Linux; Android 16; Mobile) AppleWebKit/537.36 Chrome/67.0.3396.99 Safari/537.36",
		}).
		SetBody(loginBody).
		Post(loginURL)
	if err != nil {
		return "", fmt.Errorf("login to 139 Mail with cloud ticket: %w", err)
	}
	if loginResp.StatusCode() < http.StatusOK || loginResp.StatusCode() >= http.StatusMultipleChoices {
		return "", fmt.Errorf("cloud-ticket mail login returned HTTP %d", loginResp.StatusCode())
	}

	loginResult := parseDriveMailLoginResponse(loginResp.Body())
	if loginResult.Code != "S_OK" {
		return "", fmt.Errorf("cloud-ticket mail login failed: code=%s summary=%s", loginResult.Code, loginResult.Summary)
	}

	sid := strings.TrimSpace(loginResult.Var.SID)
	if sid == "" && loginResult.Var.LoginSuccessURL != "" {
		if parsed, parseErr := url.Parse(loginResult.Var.LoginSuccessURL); parseErr == nil {
			sid = parsed.Query().Get("sid")
		}
	}
	rmkey := strings.TrimSpace(loginResult.Var.RMKEY)

	cookies := mergeMailCookieHeader("", loginResp.Cookies())
	for _, cookie := range cookiepkg.Parse(cookies) {
		switch cookie.Name {
		case "Os_SSo_Sid", "sid":
			if sid == "" {
				sid = cookie.Value
			}
		case "RMKEY":
			if rmkey == "" {
				rmkey = cookie.Value
			}
		}
	}
	if sid == "" || rmkey == "" {
		return "", errors.New("cloud-ticket mail login did not return sid or RMKEY")
	}

	cookieList := cookiepkg.Parse(cookies)
	cookieList = cookiepkg.SetCookie(cookieList, "Os_SSo_Sid", sid)
	cookieList = cookiepkg.SetCookie(cookieList, "sid", sid)
	cookieList = cookiepkg.SetCookie(cookieList, "RMKEY", rmkey)
	return cookiepkg.ToString(cookieList), nil
}

func parseDriveMailLoginResponse(body []byte) driveMailLoginResponse {
	var response driveMailLoginResponse
	if jsoniter.Unmarshal(body, &response) == nil && (response.Code != "" || response.Summary != "" || response.Var.SID != "" || response.Var.RMKEY != "") {
		return response
	}
	text := string(body)
	capture := func(name string) string {
		pattern := regexp.MustCompile(`["']?` + regexp.QuoteMeta(name) + `["']?\s*:\s*["']([^"']+)`)
		if match := pattern.FindStringSubmatch(text); len(match) == 2 {
			return match[1]
		}
		return ""
	}
	response.Code = capture("code")
	response.Summary = capture("summary")
	response.Var.LoginSuccessURL = capture("loginSuccessUrl")
	response.Var.SID = capture("sid")
	response.Var.RMKEY = capture("rmkey")
	return response
}

func (d *Yun139) renewalStep2GetArtifact(sid, rmkey string) (string, error) {
	cguid := strconv.FormatInt(time.Now().UnixMilli(), 10)
	endpoint := driveRenewArtifactURL + "?func=" + url.QueryEscape("umc:getArtifact") + "&sid=" + url.QueryEscape(sid) + "&cguid=" + url.QueryEscape(cguid)
	res, err := new139RestyClient().SetRetryCount(0).R().
		SetHeaders(map[string]string{
			"Cookie":          "RMKEY=" + rmkey,
			"Content-Type":    "text/xml; charset=utf-8",
			"Accept-Encoding": "gzip",
			"User-Agent":      "okhttp/4.12.0",
		}).
		Post(endpoint)
	if err != nil {
		return "", fmt.Errorf("mail fast-login artifact exchange failed: %w", err)
	}
	if res.StatusCode() < http.StatusOK || res.StatusCode() >= http.StatusMultipleChoices {
		return "", fmt.Errorf("mail fast-login artifact exchange returned HTTP %d", res.StatusCode())
	}
	artifact := jsoniter.Get(res.Body(), "var", "artifact").ToString()
	if artifact == "" {
		if match := regexp.MustCompile(`["']artifact["']\s*:\s*["']([^"']+)`).FindSubmatch(res.Body()); len(match) == 2 {
			artifact = string(match[1])
		}
	}
	if artifact == "" {
		return "", errors.New("mail fast-login artifact exchange did not return artifact")
	}
	return artifact, nil
}

func (d *Yun139) renewalStep3ThirdPartyLogin(account, artifact string) (authorization string, userDomainID string, err error) {
	body := base.Json{
		"clientkey_decrypt": "l3TryM&Q+X7@dzwk)qP",
		"clienttype":        "886",
		"cpid":              "507",
		"dycpwd":            artifact,
		"extInfo":           base.Json{"ifOpenAccount": "0"},
		"loginMode":         "0",
		"msisdn":            account,
		"pintype":           "13",
		"secinfo":           strings.ToUpper(sha1Hash("fetion.com.cn:" + artifact)),
		"version":           "20250901",
	}
	headers := map[string]string{
		"hcy-cool-flag":       "1",
		"x-huawei-channelSrc": "10246600",
		"x-sdk-channelSrc":    "",
		"x-MM-Source":         "0",
		"x-UserAgent":         "android|23116PN5BC|android15|1.2.6|||1440x3200|10246600",
		"x-DeviceInfo":        "4|127.0.0.1|5|1.2.6|Xiaomi|23116PN5BC||02-00-00-00-00-00|android 15|1440x3200|android|||",
		"Content-Type":        "text/plain;charset=UTF-8",
		"Accept-Encoding":     "gzip",
		"User-Agent":          "okhttp/3.12.2",
	}

	layer1, err := d.yun139EncryptedRequest(driveRenewThirdLoginURL, body, headers, KEY_HEX_1, nil)
	if err != nil {
		return "", "", fmt.Errorf("mail fast-login thirdlogin failed: %w", err)
	}
	hexInner := jsoniter.Get(layer1, "data").ToString()
	if hexInner == "" {
		return "", "", errors.New("mail fast-login thirdlogin response is missing data")
	}
	key2, err := hex.DecodeString(KEY_HEX_2)
	if err != nil {
		return "", "", fmt.Errorf("decode thirdlogin layer2 key: %w", err)
	}
	innerBytes, err := hex.DecodeString(hexInner)
	if err != nil {
		return "", "", fmt.Errorf("decode thirdlogin layer2 payload: %w", err)
	}
	finalJSON, err := aes_ecb_decrypt(innerBytes, key2)
	if err != nil {
		return "", "", fmt.Errorf("decrypt thirdlogin layer2 payload: %w", err)
	}
	authToken := jsoniter.Get(finalJSON, "authToken").ToString()
	responseAccount := jsoniter.Get(finalJSON, "account").ToString()
	userDomainID = jsoniter.Get(finalJSON, "userDomainId").ToString()
	if authToken == "" || responseAccount == "" || userDomainID == "" {
		return "", "", errors.New("mail fast-login thirdlogin response is missing account, authToken, or userDomainId")
	}
	if responseAccount != account {
		return "", "", fmt.Errorf("mail fast-login thirdlogin returned a different account")
	}
	return base64.StdEncoding.EncodeToString([]byte("pc:" + responseAccount + ":" + authToken)), userDomainID, nil
}
