package _139

import (
	"encoding/base64"
	"strings"
	"testing"

	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

const validHjqDeviceProfile = `{"phone_id":"pid","phone_model":"model","phone_brand":"brand","device_uuid":"uuid","mac_address":"00:11:22:33:44:55","app_version":"9.9.0","android_version":"15","phone_type":"model"}`

func TestParseHjqDeviceProfile(t *testing.T) {
	profile, err := parseHjqDeviceProfile(validHjqDeviceProfile)
	require.NoError(t, err)
	assert.Equal(t, "pid", profile.PhoneID)
	assert.Equal(t, "uuid", profile.DeviceUUID)

	_, err = parseHjqDeviceProfile(`{"phone_id":"pid"}`)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "device_profile missing")
}

func TestBuildHjqStep1BodyHashesPassword(t *testing.T) {
	profile, err := parseHjqDeviceProfile(validHjqDeviceProfile)
	require.NoError(t, err)
	d := &Yun139{Addition: Addition{Username: "13800138000", Password: "p@ssword"}}
	body := buildHjqStep1Body(d, profile, "123456789")

	assert.Equal(t, sha1Hash("fetion.com.cn:p@ssword"), body["authdata"])
	assert.Equal(t, hjqMD5("p@ssword"), body["virtualAuthdata"])
	assert.Equal(t, "123456789", body["timestamp"])
	assert.Equal(t, "13800138000", body["phoneNumber"])

	encoded, err := utils.Json.Marshal(body)
	require.NoError(t, err)
	assert.False(t, strings.Contains(string(encoded), "p@ssword"), "plaintext password must not be sent")
}

func TestBuildHjqStep3Body(t *testing.T) {
	body := buildHjqStep3Body("13800138000", "token-value")
	assert.Equal(t, "673", body["clienttype"])
	assert.Equal(t, "295", body["cpid"])
	assert.Equal(t, "token-value", body["dycpwd"])
	assert.Equal(t, strings.ToUpper(sha1Hash("fetion.com.cn:token-value")), body["secinfo"])
}

func TestHjqAuthorizationFromPayload(t *testing.T) {
	auth, userDomainID, err := hjqAuthorizationFromPayload([]byte(`{"account":"13800138000","authToken":"token|x|y|9999999999999","userDomainId":"ud-1"}`))
	require.NoError(t, err)
	assert.Equal(t, "ud-1", userDomainID)
	decoded, err := base64.StdEncoding.DecodeString(auth)
	require.NoError(t, err)
	assert.Equal(t, "pc:13800138000:token|x|y|9999999999999", string(decoded))

	_, _, err = hjqAuthorizationFromPayload([]byte(`{"account":"13800138000"}`))
	require.Error(t, err)
}
