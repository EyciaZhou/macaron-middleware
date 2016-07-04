package avatar
import (
	"time"
	"crypto/hmac"
	"crypto/sha1"
	"encoding/json"
	"encoding/base64"
	"strings"
	"gopkg.in/macaron.v1"
	"net/http"
	"errors"
	"io/ioutil"
	"net/url"
	"strconv"
	"github.com/EyciaZhou/macaron-middleware/user"
	"github.com/Sirupsen/logrus"
)

type Option struct {
	AccessKey string
	SecretKey string
	Bucket string

	QiniuCDNUrl string

	Host string
	APIPrefix string
}

type putPolicy struct {
	Scope string `json:"scope"`
	Deadline int64 `json:"deadline"`
	CallbackUrl string `json:"callbackUrl"`
	CallbackBody string `json:"callbackBody"`

	EndUser string `json:"endUser"`
	FsizeLimit int `json:"fsizeLimit"`
	DetectMime int `json:"detectMime"`
	MimeLimit string `json:"mimeLimit"`
}

type QiniuAvatar struct {
	Option
}

func (p *QiniuAvatar)makeupPutPolicy(username string) *putPolicy {
	return &putPolicy{
		Scope:p.Bucket + ":" + username,
		Deadline:time.Now().Unix() + 3600,
		CallbackUrl:p.Host + p.APIPrefix + "/callback",
		CallbackBody:`endUser=$(endUser)`,
		EndUser:username,
		FsizeLimit:1*1024*1024, //1m
		DetectMime:1,
		MimeLimit:`image/jpeg;image/png`,
	}
}

func hmac_sha1(bs []byte, key string) []byte {
	_hmac := hmac.New(sha1.New, ([]byte)(key))
	_hmac.Write(bs)
	return _hmac.Sum(nil)
}

func (p *QiniuAvatar) MakeupUploadToken(username string) (string){
	putPolicyStuct := p.makeupPutPolicy(username);
	bs, _ := json.Marshal(putPolicyStuct)
	encodedPutPolicy := base64.URLEncoding.EncodeToString(bs)

	encodedSign := base64.URLEncoding.EncodeToString(hmac_sha1(([]byte)(encodedPutPolicy), p.SecretKey))

	return p.AccessKey + ":" + encodedSign + ":" + encodedPutPolicy
}

func (p *QiniuAvatar) callbackHeaderAuthorization(Authorization string, Path string, Body string) bool {
	if (strings.Index(Authorization, "QBox ") != 0) {
		return false
	}
	auth := strings.Split(Authorization[5:], ":")
	if (len(auth) != 2 || auth[0] != p.AccessKey) {
		return false
	}
	return base64.URLEncoding.EncodeToString(hmac_sha1(([]byte)(Path + "\n" + Body), p.SecretKey)) == auth[1]
}

func (p *QiniuAvatar) CallbackHandler(ctx *macaron.Context, userProxy *user.UserProxy,  log *logrus.Logger) {
	reason := ""
	e := (error)(nil)

	defer func() {
		if e != nil {
			log.Errorln("QiniuAvatar:Callback", reason, e.Error())
			ctx.JSON(http.StatusOK, errors.New(reason))
		}
	}()

	defer ctx.Req.Body().ReadCloser().Close()
	body_bs, err := ioutil.ReadAll(ctx.Req.Body().ReadCloser())
	if err != nil {
		reason, e = "callback:读取Body失败", err
		return
	}
	body := (string)(body_bs)
	if (!p.callbackHeaderAuthorization(ctx.Req.Header.Get("Authorization"), ctx.Req.URL.Path, body)) {
		reason, e = "callback:验证Authorization失败", errors.New("验证Authorization失败")
		return
	}
	vals, err := url.ParseQuery((string)(body))
	if err != nil {
		reason, e = "callback:非法Query", err
		return
	}
	username := vals.Get("endUser")
	if username == "" {
		reason, e = "callback, 上传成功,未知错误", errors.New((string)(body))
		return
	}

	value := strconv.FormatInt(time.Now().Unix(), 10)
	reason, e = "服务端错误", userProxy.ChangeHead(username, value)

	if e == nil {
		ctx.JSON(http.StatusOK, p.GetHead(username, value))
	}

	return
}

func (p *QiniuAvatar) HeadTokenHandler(ctx *macaron.Context, userInfo *user.UserInfo, userProxy *user.UserProxy) {
	if !userProxy.MustLogined(ctx, userInfo) {
		return
	}
	ctx.JSON(http.StatusOK, p.MakeupUploadToken(userInfo.Id))
}

func (p *QiniuAvatar) GetHead(username string, value string) (string) {
	return p.QiniuCDNUrl + username + "-head?v=" + value
}

func (p *QiniuAvatar) RouterGroup(m *macaron.Macaron) {
	m.Get(p.APIPrefix + "/head_token", p.HeadTokenHandler)
	m.Get(p.APIPrefix + "/callback", p.CallbackHandler)
}

func QiniuAvatarStore(opt Option, m *macaron.Macaron) macaron.Handler {
	qiniuAvatarStore := &QiniuAvatar{
		opt,
	}

	qiniuAvatarStore.RouterGroup(m)

	return func(userInfo *user.UserInfo) {
		if userInfo != nil {
			userInfo.Head = qiniuAvatarStore.GetHead(userInfo.Id, userInfo.Head)
		}
	}
}