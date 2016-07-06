package logrus_mw
import (
	"gopkg.in/macaron.v1"
	"github.com/Sirupsen/logrus"
	"os"
)

type Option struct {
	DisableColors bool
	Level logrus.Level
}

func Logrus(option Option, m *macaron.Macaron) macaron.Handler {
	log := &logrus.Logger{
		Out:       os.Stderr,
		Formatter: &logrus.TextFormatter{
			ForceColors:!option.DisableColors,
			DisableColors:option.DisableColors,
		},
		Hooks:     make(logrus.LevelHooks),
		Level:     option.Level,
	}
	m.Map(log)

	return func() {
	}
}