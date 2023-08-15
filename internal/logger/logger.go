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
		logrus.SetOutput(f)
	}

	if debug {
		logrus.SetLevel(logrus.DebugLevel)
	}

	var logFormatter logrus.TextFormatter
	logFormatter.FullTimestamp = true
	if !logTimestamp {
		logFormatter.DisableTimestamp = true
	}
	logrus.SetFormatter(&logFormatter)

	logrus.SetReportCaller(logCaller)

	ldapserver.SetupLogger(logrus.StandardLogger())

	return l, nil
}
