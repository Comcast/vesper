// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"encoding/json"
	"path/filepath"
	"syscall"
	"time"
	"strings"
	"github.com/httprouter"
	"github.com/cors"
	"github.com/comcast/irislogger"
)

var (
	info    *irislogger.Logger
	config Configuration
)

// The first letter of the struct elements must be upper case in order to export them
// The JSON decoder will not use struct elements that are not exported
type Configuration struct {
	LogFile string `json:"log_file"`
	LogFileMaxSize int64 `json:"log_file_max_size"`
	Fqdn string `json:"fqdn"`
	SslCertFile string `json:"ssl_cert_file"`
	SslKeyFile string `json:"ssl_key_file"`
	Authentication map[string]interface{} `json:"authentication"`	// unmarshals a JSON object into a string-keyed map
}

// ErrorBlob -- This is a standard error object
type ErrorBlob struct {
	ReasonCode string `json:"reasonCode"`
	ReasonString string `json:"reasonString"`
}

// Read from configuration file and validate keys exist
func getConfiguration(f string) (err error) {
	file, err := os.Open(f)
	if err == nil {
		decoder := json.NewDecoder(file)
		err = decoder.Decode(&config)
	}
	return
}

// Instantiate logging objects
func initializeLogging() (err error) {
	err = os.MkdirAll(filepath.Dir(config.LogFile), 0755)
	if err == nil {
		info = irislogger.New(config.LogFile, config.LogFileMaxSize)
	}
	return
}

// function to log in specific format
func logInfo(format string, args ...interface{}) {
	info.Printf(time.Now().Format("2006-01-02 15:04:05.000") + " vesper=" + config.Fqdn + ", Code=info, " + format, args ...)
}

// function to log in specific format
func logError(format string, args ...interface{}) {
	info.Printf(time.Now().Format("2006-01-02 15:04:05.000") + " vesper=" + config.Fqdn + ", Code=Error, " + format, args ...)
}

// Read config file
// Instantiate logging
func init() {
	if (len(os.Args) != 2) {
		log.Fatal("The config file (ABSOLUTE PATH + FILE NAME) must be the only command line arguement")
	}
	// read config
	err  := getConfiguration(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// Initialize logging
	err = initializeLogging()
	if err != nil {
		log.Fatal(err)
	}
}

func handleSignals() {
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	signal.Notify(c, syscall.SIGTERM)
	go func() {
		<-c
		logInfo("Type=vesperStop, Message=Shutting down vesper .... ")
		os.Exit(1)
	}()
}

//
func main() {
	logInfo("Type=vesperStart, Message=Starting vesper .... ")
	handleSignals()

	router := httprouter.New()
	router.GET("/v1/version", version)
	router.POST("/stir/v1/signing", signRequest)
	router.POST("/stir/v1/verification", verifyRequest)

	// Start the service.
	// Note: netstats -plnt shows a IPv6 TCP socket listening on localhost:9000
	//       but no IPv4 TCP socket. This is not an issue
	c := cors.New(cors.Options{
		AllowedMethods: []string{"GET", "POST"},
		AllowedHeaders: []string{"accept", "Content-Type", "Authorization"},
		AllowCredentials: true,
	})
	handler := c.Handler(router)
	errs := make(chan error)

	// Start HTTP server
 	go func() {
		logInfo("Type=vesperHttpServiceStart, Message=Staring HTTP service on port 80 ...")
		// Start the service.
		// Note: netstats -plnt shows a IPv6 TCP socket listening on ":80"
		//       but no IPv4 TCP socket. This is not an issue
		if err := http.ListenAndServe(":80", handler); err != nil {
			errs <- err
		}
	 }()

	// Start HTTPS server only if cert and key file exist
	if (len(strings.TrimSpace(config.SslCertFile)) > 0) && (len(strings.TrimSpace(config.SslKeyFile)) > 0) {
		go func() {
			logInfo("Type=vesperHttpsServiceStart, Message=Staring HTTPS service on port 443 ...")
			// Note: netstats -plnt shows a IPv6 TCP socket listening on ":443"
			//       but no IPv4 TCP socket. This is not an issue
			if err := http.ListenAndServeTLS(":443", config.SslCertFile, config.SslKeyFile, handler); err != nil {
				errs <- err
			}
		}()
	}
	// This will run forever until channel receives error
	select {
	case err := <-errs:
		logError("Type=vesperHttpServiceFailure, Message=Could not start serving service due to (error: %s)", err)
	}
}
