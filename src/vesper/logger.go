package main

import (
	"os"
	"time"
	"path/filepath"
	"github.com/comcast/irislogger"
	kitlog "github.com/go-kit/kit/log"
	
	"vesper/configuration"
)

// Instantiate logging objects
func initializeLogging() (err error) {
	err = os.MkdirAll(filepath.Dir(configuration.ConfigurationInstance().LogFile), 0755)
	if err == nil {
		glogger = kitlog.NewJSONLogger(kitlog.NewSyncWriter(irislogger.New(configuration.ConfigurationInstance().LogFile, configuration.ConfigurationInstance().LogFileMaxSize)))
		glogger = kitlog.With(
			glogger,
			"timestamp", kitlog.TimestampFormat(func() time.Time { return time.Now().UTC() }, "2006-01-02 15:04:05.000"),
			"service", "VESPER",
			"host", configuration.ConfigurationInstance().LogHost,
			"version", softwareVersion,
		)
	}
	return
}

// function to log in specific format
func logInfo(keyvals ...interface{}) {
	lg := kitlog.With(
		glogger,
		"code", "info",
	)
	lg.Log(keyvals...)
}

// function to log errors
func logError(keyvals ...interface{}) {
	lg := kitlog.With(
		glogger,
		"code", "error",
	)
	lg.Log(keyvals...)
}

// function to log critical errors
func logCritical(keyvals ...interface{}) {
	lg := kitlog.With(
		glogger,
		"code", "critical",
	)
	lg.Log(keyvals...)
}
