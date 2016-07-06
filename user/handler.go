package user
import (
"gopkg.in/macaron.v1"
"github.com/go-macaron/session"
"github.com/go-macaron/cache"
	"errors"
	"time"
	"github.com/EyciaZhou/macaron-middleware/render"
	"net/http"
	"sync"
	"log"
	"reflect"
)

type Options struct {
	StoreProvider string
	DialerAddress string

	CachePrefix string
	URLPrefix string
	CacheTimeout time.Duration

	TemplateSet string

	JSONError *render.JSONError
}

type UserProxy struct {
	UserStore
	Options
}

var (
	stores = map[string](func(string, *log.Logger)UserStore){}
	storesLocker sync.Mutex
)

func RegisterStore(name string, dial func(string, *log.Logger)UserStore) {
	storesLocker.Lock()
	defer storesLocker.Unlock()
	stores[name] = dial
}

func LoginedJSON(ctx *macaron.Context, user *UserInfo, userProxy *UserProxy) {
	if user == nil {
		ctx.JSON(http.StatusUnauthorized, userProxy.Options.JSONError)
		return
	}
}

func (userProxy *UserProxy) MustLogined(ctx *macaron.Context, user *UserInfo) bool {
	if user == nil {
		ctx.JSON(http.StatusUnauthorized, userProxy.Options.JSONError)
		return false
	}
	return true
}

func UserHandler(opt Options, m *macaron.Macaron) macaron.Handler {
	dialFunc, ok := stores[opt.StoreProvider]
	if !ok {
		panic(errors.New("not registed store provider"))
	}

	store := dialFunc(opt.DialerAddress, m.GetVal(reflect.TypeOf((*log.Logger)(nil))).Interface().(*log.Logger))
	user_controller := &UserProxy{store, opt}
	user_controller.RouterGroup(m)
	m.Map(user_controller)

	return func(ctx *macaron.Context, f session.Store, cache cache.Cache) {
		var userInfo *UserInfo

		username_interface := f.Get("api_uid")
		if username_interface == nil {
			userInfo = nil
		} else {
			username := username_interface.(string)

			if v, ok := cache.Get(opt.CachePrefix + username).(*UserInfo); ok {
				userInfo = v
			} else {
				userFullInfo, err := store.GetUserInfo(username)
				if err != nil {
					//log.Errorln("UserHandler", "error on user middleware, ", err.Error())
					panic(err)
				}
				userInfo = &userFullInfo.UserInfo
				if err = cache.Put(opt.CachePrefix + username, userInfo, (int64)(opt.CacheTimeout)); err != nil {
					//log.Errorln("UserHandler", "error on user middleware, ", err.Error())
					panic(err)
				}
			}
		}
		ctx.Map(userInfo)
	}
}