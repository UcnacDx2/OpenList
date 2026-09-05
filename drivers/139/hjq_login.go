package _139

import (
	"crypto/md5"
	crypto_rand "crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	log "github.com/sirupsen/logrus"
)

const (
	loginMethodMail = "mail"
	loginMethodHJQ  = "hjq"
)

type hjqDeviceProfile struct {
	PhoneID        string `json:"phone_id"`
	PhoneModel     string `json:"phone_model"`
	PhoneBrand     string `json:"phone_brand"`
	DeviceUUID     string `json:"device_uuid"`
	MACAddress     string `json:"mac_address"`
	AppVersion     string `json:"app_version"`
	AndroidVersion string `json:"android_version"`
	PhoneType      string `json:"phone_type"`
}

func normalize139LoginMethod(raw string) (string, error) {
	method := strings.ToLower(strings.TrimSpace(raw))
	if method == "" {
		return loginMethodMail, nil
	}
	switch method {
	case loginMethodMail, loginMethodHJQ:
		return method, nil
	default:
		return "", fmt.Errorf("unsupported login_method %q; expected mail or hjq", raw)
	}
}

func parseHjqDeviceProfile(raw string) (hjqDeviceProfile, error) {
	var profile hjqDeviceProfile
	if strings.TrimSpace(raw) == "" {
		return profile, errors.New("hjq_device_profile is empty")
	}
	if err := utils.Json.UnmarshalFromString(raw, &profile); err != nil {
		return profile, fmt.Errorf("failed to parse hjq_device_profile: %w", err)
	}
	required := map[string]string{
		"phone_id":        profile.PhoneID,
		"phone_model":     profile.PhoneModel,
		"phone_brand":     profile.PhoneBrand,
		"device_uuid":     profile.DeviceUUID,
		"mac_address":     profile.MACAddress,
		"app_version":     profile.AppVersion,
		"android_version": profile.AndroidVersion,
		"phone_type":      profile.PhoneType,
	}
	for name, value := range required {
		if strings.TrimSpace(value) == "" {
			return profile, fmt.Errorf("hjq_device_profile missing %s", name)
		}
	}
	return profile, nil
}

func hjqMD5(value string) string {
	sum := md5.Sum([]byte(value))
	return hex.EncodeToString(sum[:])
}

func buildHjqStep1Body(d *Yun139, device hjqDeviceProfile, timestamp string) base.Json {
	return base.Json{
		"loginType":       "UNIAUTH_PASSWORD",
		"phoneID":         device.PhoneID,
		"phoneModel":      device.PhoneModel,
		"virtualAuthdata": hjqMD5(d.Password),
		"phoneBrand":      device.PhoneBrand,
		"authType":        "10",
		"timestamp":       timestamp,
		"deviceUuid":      device.DeviceUUID,
		"os":              "android",
		"phoneNumber":     d.Username,
		"userAccount":     d.Username,
		"authdata":        sha1Hash("fetion.com.cn:" + d.Password),
		"appid":           "01010811",
		"wifiMac":         device.MACAddress,
	}
}

func hjqAppHeaders(device hjqDeviceProfile) map[string]string {
	return map[string]string{
		"version":      device.AppVersion,
		"OS":           "2",
		"OSVersion":    device.AndroidVersion,
		"phoneType":    device.PhoneType,
		"User-Agent":   "UniApp;HjqAppCategory/Phone",
		"Content-Type": "application/json; charset=UTF-8",
	}
}

func (d *Yun139) hjqStep1PasswordLogin(device hjqDeviceProfile) (string, error) {
	const endpoint = "https://base.hjq.komect.com/base/user/passwdLogin"
	body := buildHjqStep1Body(d, device, strconv.FormatInt(time.Now().UnixMilli(), 10))
	res, err := new139RestyClient().SetRetryCount(0).R().
		SetHeaders(hjqAppHeaders(device)).
		SetBody(body).
		Post(endpoint)
	if err != nil {
		return "", fmt.Errorf("HJQ step 1 request failed: %w", err)
	}
	passID := utils.Json.Get(res.Body(), "data", "passId").ToString()
	if passID == "" {
		return "", fmt.Errorf("HJQ step 1 failed: %s", utils.Json.Get(res.Body(), "message").ToString())
	}
	return passID, nil
}

func (d *Yun139) hjqStep2GetSingleToken(passID string, device hjqDeviceProfile) (string, error) {
	endpoint := fmt.Sprintf("https://base.hjq.komect.com/login/user/getSingleToken/%s", passID)
	res, err := new139RestyClient().SetRetryCount(0).R().
		SetHeaders(hjqAppHeaders(device)).
		SetBody("{}").
		Post(endpoint)
	if err != nil {
		return "", fmt.Errorf("HJQ step 2 request failed: %w", err)
	}
	token := utils.Json.Get(res.Body(), "data", "token").ToString()
	if token == "" {
		return "", errors.New("HJQ step 2 failed: token is empty")
	}
	return token, nil
}

func buildHjqStep3Body(username, token string) base.Json {
	return base.Json{
		"clientkey_decrypt": "hejiaqin#2020#la#84dE23LT^%d9",
		"clienttype":        "673",
		"cpid":              "295",
		"dycpwd":            token,
		"extInfo":           base.Json{"ifOpenAccount": "0"},
		"loginMode":         "0",
		"msisdn":            username,
		"pintype":           "13",
		"secinfo":           strings.ToUpper(sha1Hash("fetion.com.cn:" + token)),
		"version":           "9.9.0",
	}
}

func hjqAuthorizationFromPayload(payload []byte) (authorization, userDomainID string, err error) {
	account := utils.Json.Get(payload, "account").ToString()
	authToken := utils.Json.Get(payload, "authToken").ToString()
	userDomainID = utils.Json.Get(payload, "userDomainId").ToString()
	if account == "" || authToken == "" || userDomainID == "" {
		return "", "", errors.New("HJQ login response missing account, authToken or userDomainId")
	}
	authorization = base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("pc:%s:%s", account, authToken)))
	return authorization, userDomainID, nil
}

func (d *Yun139) hjqStep3ThirdPartyLogin(token string, device hjqDeviceProfile) (string, error) {
	const endpoint = "https://user-njs.yun.139.com/user/thirdlogin"
	key1, err := hex.DecodeString(KEY_HEX_1)
	if err != nil {
		return "", fmt.Errorf("HJQ step 3 decode key1: %w", err)
	}
	iv := make([]byte, 16)
	if _, err := crypto_rand.Read(iv); err != nil {
		return "", fmt.Errorf("HJQ step 3 generate IV: %w", err)
	}
	sortedJSON, err := sortedJsonStringify(buildHjqStep3Body(d.Username, token))
	if err != nil {
		return "", fmt.Errorf("HJQ step 3 stringify request: %w", err)
	}
	encrypted, err := aesCbcEncrypt([]byte(sortedJSON), key1, iv)
	if err != nil {
		return "", fmt.Errorf("HJQ step 3 encrypt request: %w", err)
	}
	payload := base64.StdEncoding.EncodeToString(append(iv, encrypted...))

	res, err := new139RestyClient().SetRetryCount(0).R().
		SetHeaders(map[string]string{
			"Host":                "user-njs.yun.139.com",
			"hcy-cool-flag":       "1",
			"x-huawei-channelsrc": "10214502",
			"x-mm-source":         "0",
			"x-useragent":         fmt.Sprintf("androidsdk|%s|android%s|6.1.1.0|||1220x2574|", device.PhoneType, device.AndroidVersion),
			"x-deviceinfo":        fmt.Sprintf("1|127.0.0.1|5|6.1.1.0|%s|%s|%s|android %s|1220x2574|android|||", device.PhoneBrand, device.PhoneType, device.DeviceUUID, device.AndroidVersion),
			"content-type":        "application/json; charset=utf-8",
			"user-agent":          "okhttp/4.11.0",
		}).
		SetBody(payload).
		Post(endpoint)
	if err != nil {
		return "", fmt.Errorf("HJQ step 3 request failed: %w", err)
	}
	if res.StatusCode() != 200 {
		return "", fmt.Errorf("HJQ step 3 unexpected status: %d", res.StatusCode())
	}

	raw := []byte(strings.TrimSpace(string(res.Body())))
	if len(raw) == 0 {
		return "", errors.New("HJQ step 3 response is empty")
	}
	if raw[0] == '{' {
		message := utils.Json.Get(raw, "message").ToString()
		if message == "" {
			message = "plain JSON error response"
		}
		return "", fmt.Errorf("HJQ step 3 failed: %s", message)
	}

	decoded, err := base64.StdEncoding.DecodeString(string(raw))
	if err != nil {
		return "", fmt.Errorf("HJQ step 3 response base64 decode failed: %w", err)
	}
	if len(decoded) < 16 {
		return "", errors.New("HJQ step 3 encrypted response is too short")
	}
	decryptedL1, err := aesCbcDecrypt(decoded[16:], key1, decoded[:16])
	if err != nil {
		return "", fmt.Errorf("HJQ step 3 first-layer decrypt failed: %w", err)
	}
	hexInner := utils.Json.Get(decryptedL1, "data").ToString()
	if hexInner == "" {
		return "", errors.New("HJQ step 3 first-layer response missing data")
	}
	inner, err := hex.DecodeString(hexInner)
	if err != nil {
		return "", fmt.Errorf("HJQ step 3 decode inner payload: %w", err)
	}
	key2, err := hex.DecodeString(KEY_HEX_2)
	if err != nil {
		return "", fmt.Errorf("HJQ step 3 decode key2: %w", err)
	}
	finalPayload, err := aes_ecb_decrypt(inner, key2)
	if err != nil {
		return "", fmt.Errorf("HJQ step 3 second-layer decrypt failed: %w", err)
	}
	authorization, userDomainID, err := hjqAuthorizationFromPayload(finalPayload)
	if err != nil {
		return "", err
	}
	d.UserDomainID = userDomainID
	return authorization, nil
}

func (d *Yun139) loginWithMailPasswordFromSelector() (string, error) {
	if d.Username == "" || d.Password == "" {
		return "", errors.New("username or password is empty")
	}

	passID, err := d.step1_password_login()
	if err != nil {
		return "", err
	}
	log.Info("[139yun] Mail login step 1 succeeded")

	token, err := d.step2_get_single_token(passID)
	if err != nil {
		return "", err
	}
	log.Info("[139yun] Mail login step 2 succeeded")

	newAuth, err := d.step3_third_party_login(token)
	if err != nil {
		return "", err
	}
	log.Info("[139yun] Mail login step 3 succeeded; authorization generated")

	d.Authorization = newAuth
	op.MustSaveDriverStorage(d)
	return newAuth, nil
}

func (d *Yun139) loginWithSelectedHjqPassword() (string, error) {
	if strings.TrimSpace(d.Username) == "" || strings.TrimSpace(d.Password) == "" {
		return "", errors.New("username or password is empty")
	}
	device, err := parseHjqDeviceProfile(d.HJQDeviceProfile)
	if err != nil {
		return "", err
	}

	log.Info("[139yun] HJQ login step 1 started")
	passID, err := d.hjqStep1PasswordLogin(device)
	if err != nil {
		return "", err
	}
	log.Info("[139yun] HJQ login step 1 succeeded")

	log.Info("[139yun] HJQ login step 2 started")
	token, err := d.hjqStep2GetSingleToken(passID, device)
	if err != nil {
		return "", err
	}
	log.Info("[139yun] HJQ login step 2 succeeded")

	log.Info("[139yun] HJQ login step 3 started")
	authorization, err := d.hjqStep3ThirdPartyLogin(token, device)
	if err != nil {
		return "", err
	}
	d.Authorization = authorization
	op.MustSaveDriverStorage(d)
	log.Info("[139yun] HJQ login succeeded; authorization generated")
	return authorization, nil
}

// loginWithHjqPassword is the dispatch hook called by loginWithPassword whenever
// login_method is non-empty. New configurations default it to "mail", while
// legacy configurations with an empty value continue through the old mail path.
func (d *Yun139) loginWithHjqPassword() (string, error) {
	method, err := normalize139LoginMethod(d.DeviceProfile)
	if err != nil {
		return "", err
	}
	switch method {
	case loginMethodMail:
		return d.loginWithMailPasswordFromSelector()
	case loginMethodHJQ:
		return d.loginWithSelectedHjqPassword()
	default:
		return "", fmt.Errorf("unsupported login_method %q", method)
	}
}
