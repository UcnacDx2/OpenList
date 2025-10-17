package _139

import (
	"bytes"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/sha1"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/driver"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/internal/op"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils/random"
	"github.com/go-resty/resty/v2"
	jsoniter "github.com/json-iterator/go"
	log "github.com/sirupsen/logrus"
)

// do others that not defined in Driver interface
func (d *Yun139) isFamily() bool {
	return d.Type == "family"
}

func encodeURIComponent(str string) string {
	r := url.QueryEscape(str)
	r = strings.Replace(r, "+", "%20", -1)
	r = strings.Replace(r, "%21", "!", -1)
	r = strings.Replace(r, "%27", "'", -1)
	r = strings.Replace(r, "%28", "(", -1)
	r = strings.Replace(r, "%29", ")", -1)
	r = strings.Replace(r, "%2A", "*", -1)
	return r
}

func calSign(body, ts, randStr string) string {
	body = encodeURIComponent(body)
	strs := strings.Split(body, "")
	sort.Strings(strs)
	body = strings.Join(strs, "")
	body = base64.StdEncoding.EncodeToString([]byte(body))
	res := utils.GetMD5EncodeStr(body) + utils.GetMD5EncodeStr(ts+":"+randStr)
	res = strings.ToUpper(utils.GetMD5EncodeStr(res))
	return res
}

func getTime(t string) time.Time {
	stamp, _ := time.ParseInLocation("20060102150405", t, utils.CNLoc)
	return stamp
}

func (d *Yun139) refreshToken() error {
	if d.ref != nil {
		return d.ref.refreshToken()
	}
	decode, err := base64.StdEncoding.DecodeString(d.Authorization)
	if err != nil {
		return fmt.Errorf("authorization decode failed: %s", err)
	}
	decodeStr := string(decode)
	splits := strings.Split(decodeStr, ":")
	if len(splits) < 3 {
		return fmt.Errorf("authorization is invalid, splits < 3")
	}
	d.Account = splits[1]
	strs := strings.Split(splits[2], "|")
	if len(strs) < 4 {
		return fmt.Errorf("authorization is invalid, strs < 4")
	}
	expiration, err := strconv.ParseInt(strs[3], 10, 64)
	if err != nil {
		return fmt.Errorf("authorization is invalid")
	}
	expiration -= time.Now().UnixMilli()
	if expiration > 1000*60*60*24*15 {
		// Authorization有效期大于15天无需刷新
		return nil
	}
	if expiration < 0 {
		return fmt.Errorf("authorization has expired")
	}

	url := "https://aas.caiyun.feixin.10086.cn:443/tellin/authTokenRefresh.do"
	var resp RefreshTokenResp
	reqBody := "<root><token>" + splits[2] + "</token><account>" + splits[1] + "</account><clienttype>656</clienttype></root>"
	_, err = base.RestyClient.R().
		ForceContentType("application/xml").
		SetBody(reqBody).
		SetResult(&resp).
		Post(url)
	if err != nil || resp.Return != "0" {
		log.Warnf("139yun: failed to refresh token with old token: %v, desc: %s. trying to login with password.", err, resp.Desc)
		newAuth, loginErr := d.loginWithPassword()
		if loginErr != nil {
			return fmt.Errorf("failed to login with password after refresh failed: %w", loginErr)
		}
		d.Authorization = newAuth
		op.MustSaveDriverStorage(d)
		return nil
	}

	d.Authorization = base64.StdEncoding.EncodeToString([]byte(splits[0] + ":" + splits[1] + ":" + resp.Token))
	op.MustSaveDriverStorage(d)
	return nil
}

func (d *Yun139) request(url string, method string, callback base.ReqCallback, resp interface{}) ([]byte, error) {
	req := base.RestyClient.R()
	randStr := random.String(16)
	ts := time.Now().Format("2006-01-02 15:04:05")
	if callback != nil {
		callback(req)
	}
	body, err := utils.Json.Marshal(req.Body)
	if err != nil {
		return nil, err
	}
	sign := calSign(string(body), ts, randStr)
	svcType := "1"
	if d.isFamily() {
		svcType = "2"
	}
	req.SetHeaders(map[string]string{
		"Accept":         "application/json, text/plain, */*",
		"CMS-DEVICE":     "default",
		"Authorization":  "Basic " + d.getAuthorization(),
		"mcloud-channel": "1000101",
		"mcloud-client":  "10701",
		//"mcloud-route": "001",
		"mcloud-sign": fmt.Sprintf("%s,%s,%s", ts, randStr, sign),
		//"mcloud-skey":"",
		"mcloud-version":         "7.14.0",
		"Origin":                 "https://yun.139.com",
		"Referer":                "https://yun.139.com/w/",
		"x-DeviceInfo":           "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||",
		"x-huawei-channelSrc":    "10000034",
		"x-inner-ntwk":           "2",
		"x-m4c-caller":           "PC",
		"x-m4c-src":              "10002",
		"x-SvcType":              svcType,
		"Inner-Hcy-Router-Https": "1",
	})

	var e BaseResp
	req.SetResult(&e)
	log.Debugf("[139] request: %s %s, body: %s", method, url, string(body))
	res, err := req.Execute(method, url)
	if err != nil {
		log.Debugf("[139] request error: %v", err)
		return nil, err
	}
	log.Debugf("[139] response body: %s", res.String())
	if !e.Success {
		return nil, errors.New(e.Message)
	}
	if resp != nil {
		err = utils.Json.Unmarshal(res.Body(), resp)
		if err != nil {
			return nil, err
		}
	}
	return res.Body(), nil
}

func (d *Yun139) requestRoute(data interface{}, resp interface{}) ([]byte, error) {
	url := "https://user-njs.yun.139.com/user/route/qryRoutePolicy"
	req := base.RestyClient.R()
	randStr := random.String(16)
	ts := time.Now().Format("2006-01-02 15:04:05")
	callback := func(req *resty.Request) {
		req.SetBody(data)
	}
	if callback != nil {
		callback(req)
	}
	body, err := utils.Json.Marshal(req.Body)
	if err != nil {
		return nil, err
	}
	sign := calSign(string(body), ts, randStr)
	svcType := "1"
	if d.isFamily() {
		svcType = "2"
	}
	req.SetHeaders(map[string]string{
		"Accept":         "application/json, text/plain, */*",
		"CMS-DEVICE":     "default",
		"Authorization":  "Basic " + d.getAuthorization(),
		"mcloud-channel": "1000101",
		"mcloud-client":  "10701",
		//"mcloud-route": "001",
		"mcloud-sign": fmt.Sprintf("%s,%s,%s", ts, randStr, sign),
		//"mcloud-skey":"",
		"mcloud-version":         "7.14.0",
		"Origin":                 "https://yun.139.com",
		"Referer":                "https://yun.139.com/w/",
		"x-DeviceInfo":           "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||",
		"x-huawei-channelSrc":    "10000034",
		"x-inner-ntwk":           "2",
		"x-m4c-caller":           "PC",
		"x-m4c-src":              "10002",
		"x-SvcType":              svcType,
		"Inner-Hcy-Router-Https": "1",
	})

	var e BaseResp
	req.SetResult(&e)
	res, err := req.Execute(http.MethodPost, url)
	log.Debugln(res.String())
	if !e.Success {
		return nil, errors.New(e.Message)
	}
	if resp != nil {
		err = utils.Json.Unmarshal(res.Body(), resp)
		if err != nil {
			return nil, err
		}
	}
	return res.Body(), nil
}

func (d *Yun139) post(pathname string, data interface{}, resp interface{}) ([]byte, error) {
	return d.request("https://yun.139.com"+pathname, http.MethodPost, func(req *resty.Request) {
		req.SetBody(data)
	}, resp)
}

func (d *Yun139) getFiles(catalogID string) ([]model.Obj, error) {
	start := 0
	limit := 100
	files := make([]model.Obj, 0)
	for {
		data := base.Json{
			"catalogID":       catalogID,
			"sortDirection":   1,
			"startNumber":     start + 1,
			"endNumber":       start + limit,
			"filterType":      0,
			"catalogSortType": 0,
			"contentSortType": 0,
			"commonAccountInfo": base.Json{
				"account":     d.getAccount(),
				"accountType": 1,
			},
		}
		var resp GetDiskResp
		_, err := d.post("/orchestration/personalCloud/catalog/v1.0/getDisk", data, &resp)
		if err != nil {
			return nil, err
		}
		for _, catalog := range resp.Data.GetDiskResult.CatalogList {
			f := model.Object{
				ID:       catalog.CatalogID,
				Name:     catalog.CatalogName,
				Size:     0,
				Modified: getTime(catalog.UpdateTime),
				Ctime:    getTime(catalog.CreateTime),
				IsFolder: true,
			}
			files = append(files, &f)
		}
		for _, content := range resp.Data.GetDiskResult.ContentList {
			f := model.ObjThumb{
				Object: model.Object{
					ID:       content.ContentID,
					Name:     content.ContentName,
					Size:     content.ContentSize,
					Modified: getTime(content.UpdateTime),
					HashInfo: utils.NewHashInfo(utils.MD5, content.Digest),
				},
				Thumbnail: model.Thumbnail{Thumbnail: content.ThumbnailURL},
				// Thumbnail: content.BigthumbnailURL,
			}
			files = append(files, &f)
		}
		if start+limit >= resp.Data.GetDiskResult.NodeCount {
			break
		}
		start += limit
	}
	return files, nil
}

func (d *Yun139) newJson(data map[string]interface{}) base.Json {
	common := map[string]interface{}{
		"catalogType": 3,
		"cloudID":     d.CloudID,
		"cloudType":   1,
		"commonAccountInfo": base.Json{
			"account":     d.getAccount(),
			"accountType": 1,
		},
	}
	return utils.MergeMap(data, common)
}

func (d *Yun139) familyGetFiles(catalogID string) ([]model.Obj, error) {
	pageNum := 1
	files := make([]model.Obj, 0)
	for {
		data := d.newJson(base.Json{
			"catalogID":       catalogID,
			"contentSortType": 0,
			"pageInfo": base.Json{
				"pageNum":  pageNum,
				"pageSize": 100,
			},
			"sortDirection": 1,
		})
		var resp QueryContentListResp
		_, err := d.post("/orchestration/familyCloud-rebuild/content/v1.2/queryContentList", data, &resp)
		if err != nil {
			return nil, err
		}
		path := resp.Data.Path
		if catalogID == d.RootFolderID {
			d.RootPath = path
		}
		for _, catalog := range resp.Data.CloudCatalogList {
			f := model.Object{
				ID:       catalog.CatalogID,
				Name:     catalog.CatalogName,
				Size:     0,
				IsFolder: true,
				Modified: getTime(catalog.LastUpdateTime),
				Ctime:    getTime(catalog.CreateTime),
				Path:     path, // 文件夹上一级的Path
			}
			files = append(files, &f)
		}
		for _, content := range resp.Data.CloudContentList {
			f := model.ObjThumb{
				Object: model.Object{
					ID:       content.ContentID,
					Name:     content.ContentName,
					Size:     content.ContentSize,
					Modified: getTime(content.LastUpdateTime),
					Ctime:    getTime(content.CreateTime),
					Path:     path, // 文件所在目录的Path
				},
				Thumbnail: model.Thumbnail{Thumbnail: content.ThumbnailURL},
				// Thumbnail: content.BigthumbnailURL,
			}
			files = append(files, &f)
		}
		if resp.Data.TotalCount == 0 {
			break
		}
		pageNum++
	}
	return files, nil
}

func (d *Yun139) groupGetFiles(catalogID string) ([]model.Obj, error) {
	pageNum := 1
	files := make([]model.Obj, 0)
	for {
		data := d.newJson(base.Json{
			"groupID":         d.CloudID,
			"catalogID":       path.Base(catalogID),
			"contentSortType": 0,
			"sortDirection":   1,
			"startNumber":     pageNum,
			"endNumber":       pageNum + 99,
			"path":            path.Join(d.RootFolderID, catalogID),
		})

		var resp QueryGroupContentListResp
		_, err := d.post("/orchestration/group-rebuild/content/v1.0/queryGroupContentList", data, &resp)
		if err != nil {
			return nil, err
		}
		path := resp.Data.GetGroupContentResult.ParentCatalogID
		if catalogID == d.RootFolderID {
			d.RootPath = path
		}
		for _, catalog := range resp.Data.GetGroupContentResult.CatalogList {
			f := model.Object{
				ID:       catalog.CatalogID,
				Name:     catalog.CatalogName,
				Size:     0,
				IsFolder: true,
				Modified: getTime(catalog.UpdateTime),
				Ctime:    getTime(catalog.CreateTime),
				Path:     catalog.Path, // 文件夹的真实Path， root:/开头
			}
			files = append(files, &f)
		}
		for _, content := range resp.Data.GetGroupContentResult.ContentList {
			f := model.ObjThumb{
				Object: model.Object{
					ID:       content.ContentID,
					Name:     content.ContentName,
					Size:     content.ContentSize,
					Modified: getTime(content.UpdateTime),
					Ctime:    getTime(content.CreateTime),
					Path:     path, // 文件所在目录的Path
				},
				Thumbnail: model.Thumbnail{Thumbnail: content.ThumbnailURL},
				// Thumbnail: content.BigthumbnailURL,
			}
			files = append(files, &f)
		}
		if (pageNum + 99) > resp.Data.GetGroupContentResult.NodeCount {
			break
		}
		pageNum = pageNum + 100
	}
	return files, nil
}

func (d *Yun139) getLink(contentId string) (string, error) {
	data := base.Json{
		"appName":   "",
		"contentID": contentId,
		"commonAccountInfo": base.Json{
			"account":     d.getAccount(),
			"accountType": 1,
		},
	}
	res, err := d.post("/orchestration/personalCloud/uploadAndDownload/v1.0/downloadRequest",
		data, nil)
	if err != nil {
		return "", err
	}
	return jsoniter.Get(res, "data", "downloadURL").ToString(), nil
}

func (d *Yun139) familyGetLink(contentId string, path string) (string, error) {
	data := d.newJson(base.Json{
		"contentID": contentId,
		"path":      path,
	})
	res, err := d.post("/orchestration/familyCloud-rebuild/content/v1.0/getFileDownLoadURL",
		data, nil)
	if err != nil {
		return "", err
	}
	return jsoniter.Get(res, "data", "downloadURL").ToString(), nil
}

func (d *Yun139) groupGetLink(contentId string, path string) (string, error) {
	data := d.newJson(base.Json{
		"contentID": contentId,
		"groupID":   d.CloudID,
		"path":      path,
	})
	res, err := d.post("/orchestration/group-rebuild/groupManage/v1.0/getGroupFileDownLoadURL",
		data, nil)
	if err != nil {
		return "", err
	}
	return jsoniter.Get(res, "data", "downloadURL").ToString(), nil
}

func unicode(str string) string {
	textQuoted := strconv.QuoteToASCII(str)
	textUnquoted := textQuoted[1 : len(textQuoted)-1]
	return textUnquoted
}

func (d *Yun139) personalRequest(pathname string, method string, callback base.ReqCallback, resp interface{}) ([]byte, error) {
	url := d.getPersonalCloudHost() + pathname
	req := base.RestyClient.R()
	randStr := random.String(16)
	ts := time.Now().Format("2006-01-02 15:04:05")
	if callback != nil {
		callback(req)
	}
	body, err := utils.Json.Marshal(req.Body)
	if err != nil {
		return nil, err
	}
	sign := calSign(string(body), ts, randStr)
	svcType := "1"
	if d.isFamily() {
		svcType = "2"
	}
	req.SetHeaders(map[string]string{
		"Accept":               "application/json, text/plain, */*",
		"Authorization":        "Basic " + d.getAuthorization(),
		"Caller":               "web",
		"Cms-Device":           "default",
		"Mcloud-Channel":       "1000101",
		"Mcloud-Client":        "10701",
		"Mcloud-Route":         "001",
		"Mcloud-Sign":          fmt.Sprintf("%s,%s,%s", ts, randStr, sign),
		"Mcloud-Version":       "7.14.0",
		"x-DeviceInfo":         "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||",
		"x-huawei-channelSrc":  "10000034",
		"x-inner-ntwk":         "2",
		"x-m4c-caller":         "PC",
		"x-m4c-src":            "10002",
		"x-SvcType":            svcType,
		"X-Yun-Api-Version":    "v1",
		"X-Yun-App-Channel":    "10000034",
		"X-Yun-Channel-Source": "10000034",
		"X-Yun-Client-Info":    "||9|7.14.0|chrome|120.0.0.0|||windows 10||zh-CN|||dW5kZWZpbmVk||",
		"X-Yun-Module-Type":    "100",
		"X-Yun-Svc-Type":       "1",
	})

	var e BaseResp
	req.SetResult(&e)
	log.Debugf("[139] personal request: %s %s, body: %s", method, url, string(body))
	res, err := req.Execute(method, url)
	if err != nil {
		log.Debugf("[139] personal request error: %v", err)
		return nil, err
	}
	log.Debugf("[139] personal response body: %s", res.String())
	if !e.Success {
		return nil, errors.New(e.Message)
	}
	if resp != nil {
		err = utils.Json.Unmarshal(res.Body(), resp)
		if err != nil {
			return nil, err
		}
	}
	return res.Body(), nil
}

func (d *Yun139) personalPost(pathname string, data interface{}, resp interface{}) ([]byte, error) {
	return d.personalRequest(pathname, http.MethodPost, func(req *resty.Request) {
		req.SetBody(data)
	}, resp)
}

func getPersonalTime(t string) time.Time {
	stamp, err := time.ParseInLocation("2006-01-02T15:04:05.999-07:00", t, utils.CNLoc)
	if err != nil {
		panic(err)
	}
	return stamp
}

func (d *Yun139) personalGetFiles(fileId string) ([]model.Obj, error) {
	files := make([]model.Obj, 0)
	nextPageCursor := ""
	for {
		data := base.Json{
			"imageThumbnailStyleList": []string{"Small", "Large"},
			"orderBy":                 "updated_at",
			"orderDirection":          "DESC",
			"pageInfo": base.Json{
				"pageCursor": nextPageCursor,
				"pageSize":   100,
			},
			"parentFileId": fileId,
		}
		var resp PersonalListResp
		_, err := d.personalPost("/file/list", data, &resp)
		if err != nil {
			return nil, err
		}
		nextPageCursor = resp.Data.NextPageCursor
		for _, item := range resp.Data.Items {
			isFolder := (item.Type == "folder")
			var f model.Obj
			if isFolder {
				f = &model.Object{
					ID:       item.FileId,
					Name:     item.Name,
					Size:     0,
					Modified: getPersonalTime(item.UpdatedAt),
					Ctime:    getPersonalTime(item.CreatedAt),
					IsFolder: isFolder,
				}
			} else {
				Thumbnails := item.Thumbnails
				var ThumbnailUrl string
				if d.UseLargeThumbnail {
					for _, thumb := range Thumbnails {
						if strings.Contains(thumb.Style, "Large") {
							ThumbnailUrl = thumb.Url
							break
						}
					}
				}
				if ThumbnailUrl == "" && len(Thumbnails) > 0 {
					ThumbnailUrl = Thumbnails[len(Thumbnails)-1].Url
				}
				f = &model.ObjThumb{
					Object: model.Object{
						ID:       item.FileId,
						Name:     item.Name,
						Size:     item.Size,
						Modified: getPersonalTime(item.UpdatedAt),
						Ctime:    getPersonalTime(item.CreatedAt),
						IsFolder: isFolder,
					},
					Thumbnail: model.Thumbnail{Thumbnail: ThumbnailUrl},
				}
			}
			files = append(files, f)
		}
		if len(nextPageCursor) == 0 {
			break
		}
	}
	return files, nil
}

func (d *Yun139) personalGetLink(fileId string) (string, error) {
	data := base.Json{
		"fileId": fileId,
	}
	res, err := d.personalPost("/file/getDownloadUrl",
		data, nil)
	if err != nil {
		return "", err
	}
	cdnUrl := jsoniter.Get(res, "data", "cdnUrl").ToString()
	if cdnUrl != "" {
		return cdnUrl, nil
	} else {
		return jsoniter.Get(res, "data", "url").ToString(), nil
	}
}

func (d *Yun139) getAuthorization() string {
	if d.ref != nil {
		return d.ref.getAuthorization()
	}
	return d.Authorization
}

func (d *Yun139) getAccount() string {
	if d.ref != nil {
		return d.ref.getAccount()
	}
	return d.Account
}

func (d *Yun139) getPersonalCloudHost() string {
	if d.ref != nil {
		return d.ref.getPersonalCloudHost()
	}
	return d.PersonalCloudHost
}

func (d *Yun139) uploadPersonalParts(ctx context.Context, partInfos []PartInfo, uploadPartInfos []PersonalPartInfo, rateLimited *driver.RateLimitReader, p *driver.Progress) error {
	// 确保数组以 PartNumber 从小到大排序
	sort.Slice(uploadPartInfos, func(i, j int) bool {
		return uploadPartInfos[i].PartNumber < uploadPartInfos[j].PartNumber
	})

	for _, uploadPartInfo := range uploadPartInfos {
		index := uploadPartInfo.PartNumber - 1
		if index < 0 || index >= len(partInfos) {
			return fmt.Errorf("invalid PartNumber %d: index out of bounds (partInfos length: %d)", uploadPartInfo.PartNumber, len(partInfos))
		}
		partSize := partInfos[index].PartSize
		log.Debugf("[139] uploading part %+v/%+v", index, len(partInfos))
		limitReader := io.LimitReader(rateLimited, partSize)
		r := io.TeeReader(limitReader, p)
		req, err := http.NewRequestWithContext(ctx, http.MethodPut, uploadPartInfo.UploadUrl, r)
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/octet-stream")
		req.Header.Set("Content-Length", fmt.Sprint(partSize))
		req.Header.Set("Origin", "https://yun.139.com")
		req.Header.Set("Referer", "https://yun.139.com/")
		req.ContentLength = partSize
		err = func() error {
			res, err := base.HttpClient.Do(req)
			if err != nil {
				return err
			}
			defer res.Body.Close()
			log.Debugf("[139] uploaded: %+v", res)
			if res.StatusCode != http.StatusOK {
				body, _ := io.ReadAll(res.Body)
				return fmt.Errorf("unexpected status code: %d, body: %s", res.StatusCode, string(body))
			}
			return nil
		}()
		if err != nil {
			return err
		}
	}
	return nil
}

func (d *Yun139) getPersonalDiskInfo(ctx context.Context) (*PersonalDiskInfoResp, error) {
	data := map[string]interface{}{
		"userDomainId": d.UserDomainID,
	}
	var resp PersonalDiskInfoResp
	_, err := d.request("https://user-njs.yun.139.com/user/disk/getPersonalDiskInfo", http.MethodPost, func(req *resty.Request) {
		req.SetBody(data)
		req.SetContext(ctx)
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}

func (d *Yun139) getFamilyDiskInfo(ctx context.Context) (*FamilyDiskInfoResp, error) {
	data := map[string]interface{}{
		"userDomainId": d.UserDomainID,
	}
	var resp FamilyDiskInfoResp
	_, err := d.request("https://user-njs.yun.139.com/user/disk/getFamilyDiskInfo", http.MethodPost, func(req *resty.Request) {
		req.SetBody(data)
		req.SetContext(ctx)
	}, &resp)
	if err != nil {
		return nil, err
	}
	return &resp, nil
}



func (d *Yun139) getDeviceProfile() string {
	if d.ref != nil {
		return d.ref.getDeviceProfile()
	}
	return d.DeviceProfile
}

func getMd5(dataStr string) string {
	hash := md5.Sum([]byte(dataStr))
	return fmt.Sprintf("%x", hash)
}

func (d *Yun139) step1_password_login(device map[string]interface{}) (string, error) {
	url := "https://base.hjq.komect.com/base/user/passwdLogin"
	h := sha1.New()
	h.Write([]byte("fetion.com.cn:" + d.Password))
	authdata := fmt.Sprintf("%x", h.Sum(nil))
	virtual_authdata := getMd5(d.Password)
	
	ts := strconv.FormatInt(time.Now().UnixMilli(), 10)

	body := base.Json{
		"loginType":       "UNIAUTH_PASSWORD",
		"phoneID":         device["phone_id"],
		"phoneModel":      device["phone_model"],
		"virtualAuthdata": virtual_authdata,
		"phoneBrand":      device["phone_brand"],
		"authType":        "10",
		"timestamp":       ts,
		"deviceUuid":      device["device_uuid"],
		"os":              "android",
		"phoneNumber":     d.Username,
		"userAccount":     d.Username,
		"authdata":        authdata,
		"appid":           "01010811",
		"wifiMac":         device["mac_address"],
	}
	
	var resp base.Json
	res, err := base.RestyClient.R().
		SetHeaders(map[string]string{
			"version":      device["app_version"].(string),
			"OS":           "2",
			"OSVersion":    device["android_version"].(string),
			"phoneType":    device["phone_type"].(string),
			"User-Agent":   "UniApp;HjqAppCategory/Phone",
			"Content-Type": "application/json; charset=UTF-8",
		}).
		SetBody(body).
		SetResult(&resp).
		Post(url)

	if err != nil {
		return "", err
	}
	
	passId := utils.Json.Get(res.Body(), "data", "passId").ToString()
	if passId == "" {
		return "", fmt.Errorf("step1 failed: %s", utils.Json.Get(res.Body(), "message").ToString())
	}
	return passId, nil
}

func (d *Yun139) step2_get_single_token(passId string, device map[string]interface{}) (string, error) {
	url := fmt.Sprintf("https://base.hjq.komect.com/login/user/getSingleToken/%s", passId)
	var resp base.Json
	res, err := base.RestyClient.R().
		SetHeaders(map[string]string{
			"version":      device["app_version"].(string),
			"OS":           "2",
			"OSVersion":    device["android_version"].(string),
			"phoneType":    device["phone_type"].(string),
			"User-Agent":   "UniApp;HjqAppCategory/Phone",
			"Content-Type": "application/json; charset=UTF-8",
		}).
		SetBody("{}").
		SetResult(&resp).
		Post(url)

	if err != nil {
		return "", err
	}

	token := utils.Json.Get(res.Body(), "data", "token").ToString()
	if token == "" {
		return "", fmt.Errorf("step2 failed: token is empty")
	}
	return token, nil
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	padding := blockSize - len(data)%blockSize
	padText := bytes.Repeat([]byte{byte(padding)}, padding)
	return append(data, padText...)
}

func pkcs7Unpad(data []byte) ([]byte, error) {
	length := len(data)
	if length == 0 {
		return nil, errors.New("pkcs7: data is empty")
	}
	unpadding := int(data[length-1])
	if unpadding > length {
		return nil, errors.New("pkcs7: invalid padding")
	}
	return data[:(length - unpadding)], nil
}

func aesCbcEncrypt(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	data = pkcs7Pad(data, block.BlockSize())
	encrypted := make([]byte, len(data))
	mode := cipher.NewCBCEncrypter(block, iv)
	mode.CryptBlocks(encrypted, data)
	return encrypted, nil
}

func aesCbcDecrypt(data, key, iv []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	if len(data)%block.BlockSize() != 0 {
		return nil, errors.New("ciphertext is not a multiple of the block size")
	}
	mode := cipher.NewCBCDecrypter(block, iv)
	decrypted := make([]byte, len(data))
	mode.CryptBlocks(decrypted, data)
	return pkcs7Unpad(decrypted)
}

func (d *Yun139) step3_third_party_login(token string, device map[string]interface{}) (string, error) {
	const URL = "https://user-njs.yun.139.com/user/thirdlogin"
	var err error
	var finalJsonBytes []byte

	key1, _ := hex.DecodeString("73634235495062495331515373756c734e7253306c673d3d")
	key2, _ := hex.DecodeString("7150714477323633586746674c337538")
	iv := []byte(random.String(16))

	h := sha1.New()
	h.Write([]byte("fetion.com.cn:" + token))
	secinfo := strings.ToUpper(fmt.Sprintf("%x", h.Sum(nil)))

	plainJson := base.Json{
		"clientkey_decrypt": "hejiaqin#2020#la#84dE23LT^%d9",
		"clienttype":        "673",
		"cpid":              "295",
		"dycpwd":            token,
		"extInfo":           base.Json{"ifOpenAccount": "0"},
		"loginMode":         "0",
		"msisdn":            d.Username,
		"pintype":           "13",
		"secinfo":           secinfo,
		"version":           "9.9.0",
	}

	sortedJson, err := sortedJsonStringify(plainJson)
	if err != nil {
		return "", fmt.Errorf("step3 failed to stringify json: %w", err)
	}

	encrypted, err := aesCbcEncrypt([]byte(sortedJson), key1, iv)
	if err != nil {
		return "", fmt.Errorf("step3 aes encrypt failed: %w", err)
	}

	payload := base64.StdEncoding.EncodeToString(append(iv, encrypted...))

	var respBody []byte
	res, err := base.RestyClient.R().
		SetHeaders(map[string]string{
			"Host":                "user-njs.yun.139.com",
			"hcy-cool-flag":       "1",
			"x-huawei-channelsrc": "10214502",
			"x-mm-source":         "0",
			"x-useragent":         fmt.Sprintf("androidsdk|%s|android%s|6.1.1.0|||1220x2574|", device["phone_type"], device["android_version"]),
			"x-deviceinfo":        fmt.Sprintf("1|127.0.0.1|5|6.1.1.0|%s|%s|%s|android %s|1220x2574|android|||", device["phone_brand"], device["phone_type"], device["device_uuid"], device["android_version"]),
			"content-type":        "application/json; charset=utf-8",
			"user-agent":          "okhttp/4.11.0",
		}).
		SetBody(payload).
		Post(URL)

	if err != nil {
		return "", err
	}
	respBody = res.Body()

	log.Debugf("Step 3 Raw Response: %s", string(respBody))

	// Check if the response is a JSON error
	if len(respBody) > 0 && respBody[0] == '{' {
		var errorResp BaseResp
		if err := utils.Json.Unmarshal(respBody, &errorResp); err == nil && !errorResp.Success {
			return "", fmt.Errorf("step3 failed with server error: %s", errorResp.Message)
		}
	}

	// Layer 1 Decryption
	decoded, err := base64.StdEncoding.DecodeString(string(respBody))
	if err != nil {
		return "", fmt.Errorf("step3 response base64 decode failed: %w. Raw response: %s", err, string(respBody))
	}
	resIv := decoded[:16]
	resCiphertext := decoded[16:]
	decryptedL1, err := aesCbcDecrypt(resCiphertext, key1, resIv)
	if err != nil {
		return "", fmt.Errorf("step3 response layer1 aes decrypt failed: %w", err)
	}

	hexInner := utils.Json.Get(decryptedL1, "data").ToString()
	if hexInner == "" {
		return "", errors.New("step3 first layer decrypt failed: data is empty")
	}

	// The provided JS code for layer 2 is AES-ECB, which doesn't use an IV.
	hexInnerBytes, _ := hex.DecodeString(hexInner)

	block, err := aes.NewCipher(key2)
	if err != nil {
		return "", fmt.Errorf("step3 failed to create cipher for layer2: %w", err)
	}
	decryptedL2 := make([]byte, len(hexInnerBytes))
	size := block.BlockSize()
	for bs, be := 0, size; bs < len(hexInnerBytes); bs, be = bs+size, be+size {
		block.Decrypt(decryptedL2[bs:be], hexInnerBytes[bs:be])
	}
	finalJsonBytes, err = pkcs7Unpad(decryptedL2)
	if err != nil {
		return "", fmt.Errorf("step3 second layer pkcs7 unpad failed: %w", err)
	}

	account := utils.Json.Get(finalJsonBytes, "account").ToString()
	authToken := utils.Json.Get(finalJsonBytes, "authToken").ToString()
	userDomainId := utils.Json.Get(finalJsonBytes, "userDomainId").ToString()
	if account == "" || authToken == "" || userDomainId == "" {
		return "", errors.New("step3 final decrypt failed: account, authToken or userDomainId is empty")
	}

	d.UserDomainID = userDomainId
	newAuthorization := base64.StdEncoding.EncodeToString([]byte(fmt.Sprintf("pc:%s:%s", account, authToken)))
	return newAuthorization, nil
}


func (d *Yun139) loginWithPassword() (string, error) {
	if d.Username == "" || d.Password == "" || d.DeviceProfile == "" {
		return "", errors.New("username, password or device_profile is empty")
	}

	var device map[string]interface{}
	err := utils.Json.UnmarshalFromString(d.DeviceProfile, &device)
	if err != nil {
		return "", fmt.Errorf("failed to parse device_profile: %w", err)
	}

	passId, err := d.step1_password_login(device)
	if err != nil {
		return "", err
	}
	log.Infof("Step 1 success, passId: %s", passId)

	token, err := d.step2_get_single_token(passId, device)
	if err != nil {
		return "", err
	}
	log.Infof("Step 2 success, token: %s", token)

	newAuth, err := d.step3_third_party_login(token, device)
	if err != nil {
		return "", err
	}
	log.Infof("Step 3 success, new authorization generated.")

	// TODO: Implement step 4, 5 if needed for other modes, but for drive, this is enough.
	d.Authorization = newAuth // Ensure Authorization is also updated before saving
	op.MustSaveDriverStorage(d)
	return newAuth, nil
}


var andAlbumAesKey, _ = hex.DecodeString("73634235495062495331515373756c734e7253306c673d3d") // Corrected AES key

// sortedJsonStringify recursively sorts keys of maps within the data and then marshals to a JSON string.
func sortedJsonStringify(data interface{}) (string, error) {
	// For the known structures, jsoniter's SortMapKeys should suffice.
	json := jsoniter.Config{
		SortMapKeys: true,
	}.Froze()
	res, err := json.MarshalToString(data)
	return res, err
}

func (d *Yun139) andAlbumRequest(pathname string, body interface{}, resp interface{}) ([]byte, error) {
	url := "https://group.yun.139.com/hcy/family/adapter/andAlbum/openApi" + pathname

	var device map[string]interface{}
	err := utils.Json.UnmarshalFromString(d.getDeviceProfile(), &device)
	if err != nil {
		return nil, fmt.Errorf("andAlbum: failed to parse device_profile: %w", err)
	}

	// 1. Marshal and sort the request body
	sortedJson, err := sortedJsonStringify(body)
	if err != nil {
		return nil, fmt.Errorf("andAlbum: failed to marshal and sort body: %w", err)
	}
	log.Errorf("andAlbum: Request Body (plaintext): %s", sortedJson)

	// 2. Encrypt the body
	iv := []byte(random.String(16))
	encryptedBody, err := aesCbcEncrypt([]byte(sortedJson), andAlbumAesKey, iv)
	if err != nil {
		return nil, fmt.Errorf("andAlbum: failed to encrypt body: %w", err)
	}
	payload := base64.StdEncoding.EncodeToString(append(iv, encryptedBody...))

	// 3. Make the request
	res, err := base.RestyClient.R().
		SetHeaders(map[string]string{
			"Host":                "group.yun.139.com",
			"authorization":       "Basic " + d.getAuthorization(),
			"x-svctype":           "2",
			"hcy-cool-flag":       "1",
			"api-version":         "v2",
			"x-huawei-channelsrc": "10214502",
			"x-sdk-channelsrc":    "",
			"x-mm-source":         "0",
			"x-useragent":         fmt.Sprintf("androidsdk|%s|android%s|6.1.1.1|||1220x1951|10214502", device["phone_type"], device["android_version"]),
			"x-deviceinfo":        fmt.Sprintf("4|127.0.0.1|5|6.1.1.1|%s|%s|%s|android %s|1220x1951|android|||", device["phone_brand"], device["phone_type"], device["device_uuid"], device["android_version"]),
			"content-type":        "application/json; charset=utf-8",
			"user-agent":          "okhttp/4.11.0",
			"accept-encoding":     "gzip",
		}).
		SetBody(payload).
		Post(url)

	if err != nil {
		return nil, err
	}

	if res.StatusCode() != 200 {
		return nil, fmt.Errorf("andAlbum: unexpected status code %d: %s", res.StatusCode(), res.String())
	}

	// 4. Decrypt the response (handle both encrypted and plain JSON)
	respBody := res.Body()
	var decryptedBytes []byte

	log.Debugf("andAlbum: Raw Response Body Length: %d", len(respBody))
	log.Debugf("andAlbum: Raw Response Body: %s", string(respBody))

	// Check if the response is likely a JSON object
	if len(respBody) > 0 && respBody[0] == '{' {
		log.Warnf("andAlbum: received a plain JSON response, not an encrypted string. Body: %s", string(respBody))
		decryptedBytes = respBody
	} else {
		// Assume it's a Base64 encoded string and try to decrypt
		cleanedBody := strings.TrimSpace(string(respBody)) // Trim whitespace

		// Add padding if missing
		if len(cleanedBody)%4 != 0 {
			padding := 4 - len(cleanedBody)%4
			for i := 0; i < padding; i++ {
				cleanedBody += "="
			}
			log.Warnf("andAlbum: Added %d padding characters to Base64 body. Cleaned body after padding: '%s'", padding, cleanedBody)
		}

		decodedResp, err := base64.StdEncoding.DecodeString(cleanedBody) // Use cleanedBody
		if err != nil {
			return nil, fmt.Errorf("andAlbum: response base64 decode failed: %w. Cleaned body: '%s'", err, cleanedBody)
		}

		if len(decodedResp) < 16 {
			return nil, fmt.Errorf("andAlbum: decoded response is too short to be encrypted. Length: %d", len(decodedResp))
		}

		respIv := decodedResp[:16]
		respCiphertext := decodedResp[16:]

		decryptedBytes, err = aesCbcDecrypt(respCiphertext, andAlbumAesKey, respIv)
		if err != nil {
			return nil, fmt.Errorf("andAlbum: response aes decrypt failed: %w", err)
		}
	}

	// 5. Unmarshal to the final response struct
	if resp != nil {
		err = utils.Json.Unmarshal(decryptedBytes, resp)
		if err != nil {
			// Log the decrypted content for debugging
			log.Debugf("andAlbum: failed to unmarshal decrypted response. Decrypted content: %s", string(decryptedBytes))
			return nil, fmt.Errorf("andAlbum: failed to unmarshal decrypted response: %w", err)
		}
		log.Errorf("andAlbum: Response Body (decrypted): %s", string(decryptedBytes))
	}

	return decryptedBytes, nil
}

func (d *Yun139) handleMetaGroupCopy(ctx context.Context, srcObj, dstDir model.Obj) error {
	pathname := "/copyContentCatalog"
	var sourceContentIDs []string
	var sourceCatalogIDs []string
	if srcObj.IsDir() {
		sourceCatalogIDs = append(sourceCatalogIDs, path.Join("root:/", srcObj.GetPath(), srcObj.GetID()))
	} else {
		sourceContentIDs = append(sourceContentIDs, path.Join("root:/", srcObj.GetPath(), srcObj.GetID()))
	}

	destCatalogID := path.Join("root:/", dstDir.GetPath(), dstDir.GetID())
	log.Debugf("[139Yun Group Copy] srcObj ID: %s, srcObj Path: %s, dstDir ID: %s, dstDir Path: %s, destCatalogID: %s", srcObj.GetID(), srcObj.GetPath(), dstDir.GetID(), dstDir.GetPath(), destCatalogID)

	body := base.Json{
		"commonAccountInfo": base.Json{
			"accountType":   "1",
			"accountUserId": d.ref.UserDomainID,
		},
		"destCatalogID":    destCatalogID,
		"destCloudID":      d.CloudID,
		"sourceCatalogIDs": sourceCatalogIDs,
		"sourceCloudID":    d.CloudID,
		"sourceContentIDs": sourceContentIDs,
	}

	var resp base.Json
	_, err := d.andAlbumRequest(pathname, body, &resp)
	return err
}
