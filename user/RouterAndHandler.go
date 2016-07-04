package user

import (
	"gopkg.in/macaron.v1"
	"github.com/go-macaron/session"
	"encoding/hex"
	"net/http"
	"errors"
	"github.com/EyciaZhou/macaron-middleware/render"
	"github.com/go-macaron/cache"
	"github.com/go-macaron/csrf"
	"github.com/go-macaron/captcha"
)

func (userProxy *UserProxy)htmlSignView(ctx *macaron.Context, sess session.Store, x csrf.CSRF) {
	if sess.Get("uid") != nil {
		ctx.Data["err_info"] = "请先登出"
		ctx.Data["csrf_token"] = x.GetToken()
		ctx.HTMLSet(http.StatusBadRequest, userProxy.TemplateSet, "login")
		return
	}
	ctx.Data["csrf_token"] = x.GetToken()
	ctx.HTMLSet(200, userProxy.TemplateSet, "sign")
}

func (userProxy *UserProxy)htmlSign(ctx *macaron.Context, cpt *captcha.Captcha, flash *session.Flash, x csrf.CSRF) {
	var (
		err_info string
	)

	defer func() {
		if err_info != "" {
			ctx.Data["csrf_token"] = x.GetToken()
			ctx.Data["err_info"] = err_info
			ctx.HTMLSet(http.StatusBadRequest, userProxy.TemplateSet, "sign")
		}
	}()

	if !cpt.VerifyReq(ctx.Req) {
		err_info = "验证码错误"
		return
	}

	username, email, pwd, retype := ctx.Query("username"), ctx.Query("email"),
					ctx.Query("password"), ctx.Query("retype")
	if retype != pwd {
		err_info = "两次输入密码不匹配"
		return
	}
	if pwd == "" {
		err_info = "密码不能为空"
		return
	}

	pwd_sha256 := Sha256(([]byte)(pwd))
	if _, e := userProxy.AddUser(username, email, pwd_sha256, username); e != nil {
		err_info = e.Error()
		return
	}

	flash.Add("succ_info", "注册成功")
	ctx.Redirect(userProxy.Options.URLPrefix + "/html/login")
}

func (userProxy *UserProxy)htmlLoginView(ctx *macaron.Context, flash *session.Flash, sess session.Store, x csrf.CSRF) {
	if sess.Get("uid") != nil {
		flash.Add("err_info", "请先登出")
		ctx.Redirect("/")
		return
	}
	ctx.Data["csrf_token"] = x.GetToken()
	ctx.HTMLSet(200, userProxy.TemplateSet, "login")
}

func (userProxy *UserProxy)htmlLogin(ctx *macaron.Context, flash *session.Flash,
				f session.Store, cpt *captcha.Captcha, x csrf.CSRF, cache cache.Cache) {
	var (
		err_info string
	)

	defer func() {
		if err_info != "" {
			ctx.Data["csrf_token"] = x.GetToken()
			ctx.Data["err_info"] = err_info
			ctx.HTMLSet(http.StatusBadRequest, userProxy.TemplateSet, "login")
		}
	}()

	if !cpt.VerifyReq(ctx.Req) {
		err_info = "验证码错误"
		return
	}

	uname, pwd := ctx.Query("uname"), ctx.Query("password")
	if pwd == "" {
		err_info = "密码不能为空"
		return
	}

	pwd_sha256 := Sha256(([]byte)(pwd))
	info, err := userProxy.VerifyPassword(uname, pwd_sha256)
	if err != nil {
		err_info = err.Error()
		return
	}

	f.Set("uid", info.Id)
	cache.Put(userProxy.Options.CachePrefix + info.Username, info, (int64)(userProxy.Options.CacheTimeout))
	flash.Add("succ_info", "登陆成功")
	ctx.Redirect("/")
}

/*
apiSign
	three query field:
		username: including alphabet and digital, start with alphabet, length can from 5 to 16
		email: normal email
		nickname: nickname
		password: password not processed
	won't set session field
	return:
		uid
 */
func (userProxy *UserProxy)apiSign(ctx *macaron.Context, f session.Store) {
	username, email, nickname := ctx.Query("username"), ctx.Query("email"), ctx.Query("nickname")
	pwd_hex := ctx.Query("password")

	pwd, err := hex.DecodeString(pwd_hex)

	if err != nil {
		ctx.JSON(http.StatusOK, errors.New("密码格式错误"))
		return
	}

	ctx.JSON(http.StatusOK, render.PackResult(userProxy.AddUser(username, email, pwd, nickname)))
}

/*
api_login
	two query field:
		uname: can be username, uid or email
		pwd: in hex format, including password after sha256

	will set session: app_uid if login success
	return:
		user_base_info
 */
func (userProxy *UserProxy)apiLogin(ctx *macaron.Context, f session.Store, cache cache.Cache) {
	uname, pwd_hex := ctx.Query("uname"), ctx.Query("pwd")
	pwd, err := hex.DecodeString(pwd_hex)

	if err != nil {
		ctx.JSON(http.StatusOK, errors.New("密码格式错误"))
		return
	}

	info, err := userProxy.VerifyPassword(uname, pwd)
	if err != nil {
		ctx.JSON(http.StatusOK, err)
		return
	}

	/*
	to protect from csrf, set uid name different from html side.
	because mobile side won't be csrf attack, so mobile side api not including
	csrf token.
	if hacker use mobile api to attack html, it will failure, because when user
	login on html side, won't set api_uid. so html side only can be attack by
	html api, but all html side api having csrf protecting.
	and user won't login using mobile api on html side.
	 */
	f.Set("api_uid", info.Id)
	cache.Put(userProxy.Options.CachePrefix + info.Username, info, (int64)(userProxy.Options.CacheTimeout))

	ctx.JSON(http.StatusOK, info)
}


func (userProxy *UserProxy) RouterGroup(m *macaron.Macaron) {
	m.Group(userProxy.URLPrefix, func() {
		m.Get("/html/sign", userProxy.htmlSignView)
		m.Get("/html/login", userProxy.htmlLoginView)
		m.Post("/html/sign", csrf.Validate, userProxy.htmlSign)
		m.Post("/html/login", csrf.Validate, userProxy.htmlLogin)
		m.Post("/api/sign", userProxy.apiSign)
		m.Post("/api/login", userProxy.apiLogin)
	})


}
