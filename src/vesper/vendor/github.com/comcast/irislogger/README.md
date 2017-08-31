# Iris Logger

### irislogger is a Go package for writing logs to rolling files.

Package irislogger provides a rolling logger.

Note that irislogger is an extension of the log [package](https://golang.org/pkg/log/)

Irislogger is intended to be one part of a logging infrastructure.
It is not an all-in-one solution, but instead is a pluggable
component at the bottom of the logging stack that simply controls the files
to which logs are written.

Irislogger assumes that only one process is writing to the output files.
Using the same irislogger configuration from multiple processes on the same
machine will result in improper behavior.


## Installation

```sh
go get github.com/comcast/irislogger
```

## Initialization

**Example**
 
```sh
package main

import "github.com/comcast/irislogger"

// Globals
var (
	Info    *irislogger.Logger
}

func init() {
	// Instantiate logging objects
	err := os.MkdirAll(filepath.Dir(filename), 0755)
	if err == nil {
		Info = irislogger.New(filename, maxsize)
	}
}

// function to log in specific format
func logInfo(format string, args ...interface{}) {
	Info.Printf(time.Now().Format("2006-01-02 15:04:05.000") + " evmgr=" + fqdn + ", Code=Info, " + format, args ...)
}

// function to log errors in specific format
func logError(format string, args ...interface{}) {
	Info.Printf(time.Now().Format("2006-01-02 15:04:05.000") + " evmgr=" + fqdn + ", Code=Error, " + format, args ...)
}


.......
```

## Logging

**Example**

```sh
....

logInfo("Type=evMgrGetRoomIdView, Message=client ip: %s; event: %s; room id: %s; starttime: %d; count: %d", client_ip, event_type, room_id, start_time, count)

....

logError("Type=evMgrDbGetFailure, Message=get_event_data_given_participants: Failed to GET record in iris_event_manager.participanthashinfo for participants : %v",  participants)

....

```