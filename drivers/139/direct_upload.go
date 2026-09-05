package _139

import (
	"context"
	"encoding/hex"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/OpenListTeam/OpenList/v4/drivers/base"
	"github.com/OpenListTeam/OpenList/v4/internal/errs"
	"github.com/OpenListTeam/OpenList/v4/internal/model"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils"
	"github.com/OpenListTeam/OpenList/v4/pkg/utils/random"
)

const (
	yun139DirectUploadTool       = "MultipartDirect"
	yun139DirectUploadSessionTTL = 2 * time.Hour
)

type yun139DirectUploadPart struct {
	PartNumber int64             `json:"part_number"`
	Offset     int64             `json:"offset"`
	Size       int64             `json:"size"`
	UploadURL  string            `json:"upload_url"`
	Method     string            `json:"method"`
	Headers    map[string]string `json:"headers,omitempty"`
}

type yun139DirectUploadInfo struct {
	SessionID string                   `json:"session_id,omitempty"`
	Completed bool                     `json:"completed"`
	Parts     []yun139DirectUploadPart `json:"parts,omitempty"`
	HasMore   bool                     `json:"has_more,omitempty"`
}

type yun139DirectUploadSession struct {
	mu sync.Mutex

	driver           *Yun139
	dstDirID         string
	fileName         string
	createdName      string
	fileSize         int64
	contentHash      string
	fileID           string
	uploadID         string
	getUploadURLPath string
	completePath     string
	groupID          string
	partInfos        []PartInfo
	nextPartIndex    int
	createdAt        time.Time
	cloudComplete    bool
}

var yun139DirectUploadSessions sync.Map

func (d *Yun139) GetDirectUploadTools() []string {
	if !d.supportsMultipartDirectUpload() {
		return nil
	}
	return []string{yun139DirectUploadTool}
}

// GetDirectUploadInfo implements the existing DirectUploader capability without
// changing OpenList's core direct-upload API. The tool value carries the action:
//
//	MultipartDirect:init:<sha256>
//	MultipartDirect:parts:<session-id>
//	MultipartDirect:complete:<session-id>
//
// All calls still pass through /fs/get_direct_upload_info, so OpenList performs
// its normal write-permission and mount-boundary checks before issuing or
// completing an upload capability.
func (d *Yun139) GetDirectUploadInfo(ctx context.Context, tool string, dstDir model.Obj, fileName string, fileSize int64) (any, error) {
	if !d.supportsMultipartDirectUpload() {
		return nil, errs.NotImplement
	}
	parts := strings.SplitN(tool, ":", 3)
	if len(parts) != 3 || parts[0] != yun139DirectUploadTool {
		return nil, errs.NotImplement
	}

	switch parts[1] {
	case "init":
		return d.initMultipartDirectUpload(ctx, dstDir, fileName, fileSize, parts[2])
	case "parts":
		return d.nextMultipartDirectUploadParts(ctx, dstDir, fileName, fileSize, parts[2])
	case "complete":
		return d.completeMultipartDirectUpload(ctx, dstDir, fileName, fileSize, parts[2])
	default:
		return nil, errs.NotImplement
	}
}

func (d *Yun139) supportsMultipartDirectUpload() bool {
	if d.isShare() {
		return false
	}
	return d.Addition.Type == MetaPersonalNew || ((d.isGroup() || d.isFamily()) && !d.UseOldStreamUpload)
}

func (d *Yun139) initMultipartDirectUpload(ctx context.Context, dstDir model.Obj, fileName string, fileSize int64, sha256 string) (*yun139DirectUploadInfo, error) {
	if fileSize < 0 {
		return nil, fmt.Errorf("file size is required for %s", yun139DirectUploadTool)
	}
	sha256 = strings.ToLower(strings.TrimSpace(sha256))
	if len(sha256) != utils.SHA256.Width {
		return nil, fmt.Errorf("valid sha256 is required for %s", yun139DirectUploadTool)
	}
	if _, err := hex.DecodeString(sha256); err != nil {
		return nil, fmt.Errorf("invalid sha256: %w", err)
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}

	createPath, getUploadURLPath, completePath := d.multipartDirectUploadPaths()
	partSize := d.getPartSize(fileSize)
	partCount := int64(1)
	if fileSize > partSize {
		partCount = (fileSize + partSize - 1) / partSize
	}

	partInfos := make([]PartInfo, 0, partCount)
	for i := int64(0); i < partCount; i++ {
		start := i * partSize
		byteSize := min(fileSize-start, partSize)
		partInfos = append(partInfos, PartInfo{
			PartNumber: i + 1,
			PartSize:   byteSize,
			ParallelHashCtx: ParallelHashCtx{
				PartOffset: start,
			},
		})
	}

	firstPartInfos := partInfos
	if len(firstPartInfos) > 100 {
		firstPartInfos = firstPartInfos[:100]
	}
	data := base.Json{
		"contentHash":          sha256,
		"contentHashAlgorithm": "SHA256",
		"contentType":          "application/octet-stream",
		"parallelUpload":       false,
		"partInfos":            firstPartInfos,
		"size":                 fileSize,
		"parentFileId":         dstDir.GetID(),
		"name":                 fileName,
		"type":                 "file",
		"fileRenameMode":       "auto_rename",
	}
	if d.isGroup() || d.isFamily() {
		if d.CloudID == "" {
			return nil, fmt.Errorf("cloud_id is required for group/family upload")
		}
		data["groupId"] = d.CloudID
		if d.isGroup() {
			data["groupType"] = 2
		} else {
			data["groupType"] = 1
		}
		data["catalogType"] = 3
		data["seqNo"] = random.String(32)
	}

	var resp PersonalUploadResp
	if _, err := d.newPost(createPath, data, &resp); err != nil {
		return nil, err
	}
	if resp.Data.Exist {
		return &yun139DirectUploadInfo{Completed: true}, nil
	}

	// A nil part list is how the existing 139 Put path identifies a rapid
	// upload that has already completed during create.
	if resp.Data.PartInfos == nil {
		if err := d.finishMultipartDirectConflict(ctx, dstDir, resp.Data.FileName, fileName); err != nil {
			return nil, err
		}
		return &yun139DirectUploadInfo{Completed: true}, nil
	}
	if resp.Data.FileId == "" || resp.Data.UploadId == "" {
		return nil, fmt.Errorf("139 direct upload returned an incomplete upload session")
	}

	var directParts []yun139DirectUploadPart
	var err error
	if fileSize == 0 && len(resp.Data.PartInfos) == 0 {
		// Empty files have no bytes to PUT, but still need the cloud complete call.
		directParts = nil
	} else {
		directParts, err = makeYun139DirectUploadParts(firstPartInfos, resp.Data.PartInfos)
		if err != nil {
			return nil, err
		}
	}

	d.cleanupMultipartDirectUploadSessions()
	sessionID := random.String(40)
	nextPartIndex := len(firstPartInfos)
	yun139DirectUploadSessions.Store(sessionID, &yun139DirectUploadSession{
		driver:           d,
		dstDirID:         dstDir.GetID(),
		fileName:         fileName,
		createdName:      resp.Data.FileName,
		fileSize:         fileSize,
		contentHash:      sha256,
		fileID:           resp.Data.FileId,
		uploadID:         resp.Data.UploadId,
		getUploadURLPath: getUploadURLPath,
		completePath:     completePath,
		groupID:          d.CloudID,
		partInfos:        partInfos,
		nextPartIndex:    nextPartIndex,
		createdAt:        time.Now(),
	})
	return &yun139DirectUploadInfo{
		SessionID: sessionID,
		Parts:     directParts,
		HasMore:   nextPartIndex < len(partInfos),
	}, nil
}

func (d *Yun139) nextMultipartDirectUploadParts(ctx context.Context, dstDir model.Obj, fileName string, fileSize int64, sessionID string) (*yun139DirectUploadInfo, error) {
	session, err := d.getMultipartDirectUploadSession(dstDir, fileName, fileSize, sessionID)
	if err != nil {
		return nil, err
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if session.cloudComplete {
		return nil, fmt.Errorf("139 direct upload session is already complete")
	}
	if session.nextPartIndex >= len(session.partInfos) {
		return &yun139DirectUploadInfo{SessionID: sessionID}, nil
	}

	end := min(session.nextPartIndex+100, len(session.partInfos))
	batchPartInfos := session.partInfos[session.nextPartIndex:end]
	data := base.Json{
		"fileId":    session.fileID,
		"uploadId":  session.uploadID,
		"partInfos": batchPartInfos,
		"commonAccountInfo": base.Json{
			"account":     d.getAccount(),
			"accountType": 1,
		},
	}
	var resp PersonalUploadUrlResp
	if _, err := d.newPost(session.getUploadURLPath, data, &resp); err != nil {
		return nil, err
	}
	directParts, err := makeYun139DirectUploadParts(batchPartInfos, resp.Data.PartInfos)
	if err != nil {
		return nil, err
	}
	session.nextPartIndex = end
	return &yun139DirectUploadInfo{
		SessionID: sessionID,
		Parts:     directParts,
		HasMore:   end < len(session.partInfos),
	}, nil
}

func (d *Yun139) completeMultipartDirectUpload(ctx context.Context, dstDir model.Obj, fileName string, fileSize int64, sessionID string) (*yun139DirectUploadInfo, error) {
	session, err := d.getMultipartDirectUploadSession(dstDir, fileName, fileSize, sessionID)
	if err != nil {
		return nil, err
	}

	session.mu.Lock()
	defer session.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if session.nextPartIndex < len(session.partInfos) {
		return nil, fmt.Errorf("139 direct upload has unissued parts")
	}

	if !session.cloudComplete {
		data := base.Json{
			"contentHash":          session.contentHash,
			"contentHashAlgorithm": "SHA256",
			"fileId":               session.fileID,
			"uploadId":             session.uploadID,
		}
		if d.isGroup() || d.isFamily() {
			data["groupId"] = session.groupID
		}
		if _, err := d.newPost(session.completePath, data, nil); err != nil {
			return nil, err
		}
		session.cloudComplete = true
	}

	if err := d.finishMultipartDirectConflict(ctx, dstDir, session.createdName, session.fileName); err != nil {
		return nil, err
	}
	yun139DirectUploadSessions.Delete(sessionID)
	return &yun139DirectUploadInfo{Completed: true}, nil
}

func (d *Yun139) getMultipartDirectUploadSession(dstDir model.Obj, fileName string, fileSize int64, sessionID string) (*yun139DirectUploadSession, error) {
	value, ok := yun139DirectUploadSessions.Load(sessionID)
	if !ok {
		return nil, fmt.Errorf("139 direct upload session not found or expired")
	}
	session, ok := value.(*yun139DirectUploadSession)
	if !ok || session.driver != d {
		return nil, fmt.Errorf("139 direct upload session does not belong to this storage")
	}
	if time.Since(session.createdAt) > yun139DirectUploadSessionTTL {
		yun139DirectUploadSessions.Delete(sessionID)
		return nil, fmt.Errorf("139 direct upload session expired")
	}
	if session.dstDirID != dstDir.GetID() || session.fileName != fileName || session.fileSize != fileSize {
		return nil, errs.PermissionDenied
	}
	return session, nil
}

func makeYun139DirectUploadParts(partInfos []PartInfo, uploadPartInfos []PersonalPartInfo) ([]yun139DirectUploadPart, error) {
	uploadURLs := make(map[int64]string, len(uploadPartInfos))
	for _, item := range uploadPartInfos {
		uploadURLs[int64(item.PartNumber)] = item.UploadUrl
	}
	directParts := make([]yun139DirectUploadPart, 0, len(partInfos))
	for _, part := range partInfos {
		uploadURL := uploadURLs[part.PartNumber]
		if uploadURL == "" {
			return nil, fmt.Errorf("139 direct upload did not return URL for part %d", part.PartNumber)
		}
		directParts = append(directParts, yun139DirectUploadPart{
			PartNumber: part.PartNumber,
			Offset:     part.ParallelHashCtx.PartOffset,
			Size:       part.PartSize,
			UploadURL:  uploadURL,
			Method:     http.MethodPut,
			Headers: map[string]string{
				"Content-Type": "application/octet-stream",
			},
		})
	}
	return directParts, nil
}

func (d *Yun139) multipartDirectUploadPaths() (createPath, getUploadURLPath, completePath string) {
	if d.isGroup() || d.isFamily() {
		return "/dynamic/file/create", "/dynamic/file/getUploadUrl", "/dynamic/file/complete"
	}
	return "/file/create", "/file/getUploadUrl", "/file/complete"
}

func (d *Yun139) finishMultipartDirectConflict(ctx context.Context, dstDir model.Obj, createdName, requestedName string) error {
	if createdName == "" || createdName == requestedName {
		return nil
	}
	// Keep the same conflict semantics as the normal 139 Put path: the cloud
	// auto-renames the new object first, then OpenList replaces the old object.
	time.Sleep(500 * time.Millisecond)
	files, err := d.List(ctx, dstDir, model.ListArgs{Refresh: true})
	if err != nil {
		return err
	}
	for _, file := range files {
		if file.GetName() != requestedName {
			continue
		}
		if err := d.Rename(ctx, file, requestedName+random.String(4)); err != nil {
			return err
		}
		if err := d.Remove(ctx, file); err != nil {
			return err
		}
		break
	}
	for _, file := range files {
		if file.GetName() != createdName {
			continue
		}
		if err := d.Rename(ctx, file, requestedName); err != nil {
			return err
		}
		break
	}
	return nil
}

func (d *Yun139) cleanupMultipartDirectUploadSessions() {
	now := time.Now()
	yun139DirectUploadSessions.Range(func(key, value any) bool {
		session, ok := value.(*yun139DirectUploadSession)
		if !ok || now.Sub(session.createdAt) > yun139DirectUploadSessionTTL {
			yun139DirectUploadSessions.Delete(key)
		}
		return true
	})
}
