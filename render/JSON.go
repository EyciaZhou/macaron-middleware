package render
import "gopkg.in/macaron.v1"

type JSONError struct {
	Errno  int
	Reason error
	Extra  interface{}
}

type JSON struct {
	Err    int `json:"err"`
	Reason string `json:"reason"`
	Data   interface{} `json:"data"`
}

//jsonFromError:
//	error should not nil
func jsonFromError(e error) *JSON {
	return &JSON{
		Err:1,
		Data:nil,
		Reason:e.Error(),
	}
}

func jsonFromResult(v interface{}) *JSON {
	return &JSON{
		Err:0,
		Data:v,
		Reason:"",
	}
}

func PackResult(v interface{}, e error) *JSON {
	if e != nil {
		return jsonFromError(e)
	}
	return jsonFromResult(v)
}

type Render struct {
	*macaron.TplRender
}

func (r *Render) JSON(status int, v interface{}) {
	if jsonError, ok := v.(*JSONError); ok {
		r.TplRender.JSON(status, &JSON{
			jsonError.Errno,
			jsonError.Reason.Error(),
			jsonError.Extra,
		})
	} else if json, ok := v.(*JSON); ok {
		r.TplRender.JSON(status, json)
	} else if err, ok := v.(error); ok {
		r.TplRender.JSON(status, jsonFromError(err))
	} else {
		r.TplRender.JSON(status, jsonFromResult(v))
	}
}

func RendererAddon() macaron.Handler {
	return func(ctx *macaron.Context, render macaron.Render) {
		ctx.MapTo(Render{render.(*macaron.TplRender)}, (*macaron.Render)(nil))
	}
}