package logger

import (
	"fmt"
	"os"

	"github.com/ps78674/ldapserver"
	"github.com/sirupsen/logrus"
)

func NewLogger(path string, debug, logTimestamp, logCaller bool) (*logrus.Logger, error) {
	l := logrus.New()

	if len(path) > 0 {
		f, err := os.OpenFile(path, os.O_RDWR|os.O_CREATE|os.O_APPEND, 0666)
		if err != nil {
			return nil, fmt.Errorf("error opening logfile: %s", err)
		}
		defer f.Close()
		l.SetOutput(f)
	}

	if debug {
		l.SetLevel(logrus.DebugLevel)
	}

	var logFormatter logrus.TextFormatter
	logFormatter.FullTimestamp = true
	if !logTimestamp {
		logFormatter.DisableTimestamp = true
	}
	l.SetFormatter(&logFormatter)

	l.SetReportCaller(logCaller)

	ldapserver.SetupLogger(l)

	return l, nil
}
