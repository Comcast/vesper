package rootcerts

import (
	kitlog "github.com/go-kit/kit/log"
)

var glogger kitlog.Logger

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
