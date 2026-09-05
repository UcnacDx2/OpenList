package _139

import (
	"reflect"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestNormalize139LoginMethod(t *testing.T) {
	method, err := normalize139LoginMethod("")
	require.NoError(t, err)
	assert.Equal(t, loginMethodMail, method)

	method, err = normalize139LoginMethod(" HJQ ")
	require.NoError(t, err)
	assert.Equal(t, loginMethodHJQ, method)

	_, err = normalize139LoginMethod("legacy")
	require.Error(t, err)
	assert.Contains(t, err.Error(), "login_method")
}

func TestLoginMethodSelectorDoesNotInferFromHJQProfile(t *testing.T) {
	d := &Yun139{Addition: Addition{
		DeviceProfile:    "mail",
		HJQDeviceProfile: validHjqDeviceProfile,
	}}
	method, err := normalize139LoginMethod(d.DeviceProfile)
	require.NoError(t, err)
	assert.Equal(t, loginMethodMail, method)

	d.DeviceProfile = "hjq"
	method, err = normalize139LoginMethod(d.DeviceProfile)
	require.NoError(t, err)
	assert.Equal(t, loginMethodHJQ, method)
}

func TestHJQLoginMethodRequiresExplicitDeviceProfile(t *testing.T) {
	d := &Yun139{Addition: Addition{
		DeviceProfile: "hjq",
		Username:      "13800138000",
		Password:      "password",
	}}
	_, err := d.loginWithHjqPassword()
	require.Error(t, err)
	assert.Contains(t, err.Error(), "hjq_device_profile is empty")
}

func TestHJQFormMetadataIsExplicit(t *testing.T) {
	typ := reflect.TypeOf(Addition{})

	loginField, ok := typ.FieldByName("DeviceProfile")
	require.True(t, ok)
	assert.Equal(t, "login_method", loginField.Tag.Get("json"))
	assert.Equal(t, "select", loginField.Tag.Get("type"))
	assert.Equal(t, "mail,hjq", loginField.Tag.Get("options"))
	assert.Equal(t, "mail", loginField.Tag.Get("default"))
	assert.Contains(t, loginField.Tag.Get("help"), "username/password")
	assert.Contains(t, loginField.Tag.Get("help"), "HJQ")

	profileField, ok := typ.FieldByName("HJQDeviceProfile")
	require.True(t, ok)
	assert.Equal(t, "hjq_device_profile", profileField.Tag.Get("json"))
	help := profileField.Tag.Get("help")
	assert.Contains(t, help, "Required only when login_method=hjq")
	assert.Contains(t, help, "phone_id")
	assert.Contains(t, help, "device_uuid")
	assert.Contains(t, help, "This is not cloud Authorization or mail cookies")
}
