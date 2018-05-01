// Copyright 2017 Comcast Cable Communications Management, LLC

package main

import (
	"log"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"syscall"
	"context"
	"time"
	"strings"
	"regexp"
	"github.com/httprouter"
	"github.com/cors"
	"github.com/comcast/irislogger"
	"vesper/configuration"
	"vesper/rootcerts"
	"vesper/sks"
	"vesper/sticr"
	"vesper/signcredentials"
)

var (
	info												*irislogger.Logger
	rootCerts										*rootcerts.RootCerts
	signingCredentials					*signcredentials.SigningCredentials
	sksCredentials							*sks.SksCredentials
	x5u													*sticr.SticrHost
	httpClient									*http.Client
	rootCertsTicker							*time.Ticker
	signingCredentialsTicker		*time.Ticker
	sksSticrTicker							*time.Ticker
	stopTicker									chan struct{}
	regexInfo										*regexp.Regexp
	regexAlg										*regexp.Regexp
	regexPpt										*regexp.Regexp
)

// ErrorBlob -- This is a standard error object
type ErrorBlob struct {
	ReasonCode string `json:"reasonCode"`
	ReasonString string `json:"reasonString"`
}

// Instantiate logging objects
func initializeLogging() (err error) {
	err = os.MkdirAll(filepath.Dir(configuration.ConfigurationInstance().LogFile), 0755)
	if err == nil {
		info = irislogger.New(configuration.ConfigurationInstance().LogFile, configuration.ConfigurationInstance().LogFileMaxSize)
	}
	return
}

// function to log in specific format
func logInfo(format string, args ...interface{}) {
	info.Printf(time.Now().Format("2006-01-02 15:04:05")+" vesper="+configuration.ConfigurationInstance().Host+", Version=" + softwareVersion + ", Code=Info, "+format, args...)
}

// function to log errors
func logError(format string, args ...interface{}) {
	info.Printf(time.Now().Format("2006-01-02 15:04:05")+" vesper="+configuration.ConfigurationInstance().Host+", Version=" + softwareVersion + ", Code=Error, "+format, args...)
}

// function to log critical errors
func logCritical(format string, args ...interface{}) {
	info.Printf(time.Now().Format("2006-01-02 15:04:05")+" vesper="+configuration.ConfigurationInstance().Host+", Version=" + softwareVersion + ", Code=Critical, "+format, args...)
}


// Read config file
// Instantiate logging
func init() {
	if (len(os.Args) != 2) {
		log.Fatal("The config file (ABSOLUTE PATH + FILE NAME) must be the only command line arguement")
	}

	// read config
	err := configuration.ConfigurationInstance().GetConfiguration(os.Args[1])
	if err != nil {
		log.Fatal(err)
	}

	// Initialize logging
	err = initializeLogging()
	if err != nil {
		log.Fatal(err)
	}

	// create http client object once - to be reused
	httpClient = &http.Client{}
	
	// initiatlize sks credentials object
	sksCredentials, err = sks.InitObject(configuration.ConfigurationInstance().SksCredentialsFile)
	if err != nil {
		logCritical("Type=sksConfig, Message=%v.... cannot start Vesper Service .... ", err)
		os.Exit(1)
	}		

	// initiatlize sticr object
	x5u, err = sticr.InitObject(configuration.ConfigurationInstance().SticrHostFile)
	if err != nil {
		logCritical("Type=sticrConfig, Message=%v.... cannot start Vesper Service .... ", err)
		os.Exit(2)
	}	
	
	// After sks credentials object is successfully initialized, initiatlize rootcerts object
	signingCredentials, err = signcredentials.InitObject(info, softwareVersion, httpClient, sksCredentials, x5u)
	if err != nil {
		logCritical("Type=signingCredentials, Message=%v.... cannot start Vesper Service .... ", err)
		os.Exit(3)
	}

	// After sks credentials object is successfully initialized, initiatlize rootcerts object
	rootCerts, err = rootcerts.InitObject(info, softwareVersion, httpClient, sksCredentials)
	if err != nil {
		logCritical("Type=rootCerts, Message=%v.... cannot start Vesper Service .... ", err)
		os.Exit(4)
	}
	
	// Compile the expression once
	regexInfo = regexp.MustCompile(`^info=<..*>$`)
	regexAlg = regexp.MustCompile(`^alg=ES256$`)
	regexPpt = regexp.MustCompile(`^ppt=shaken$`)
	
	// start periodic tickers
	// NewTicker returns a new Ticker containing a channel that will send the time with
	// a period specified by the duration argument. It adjusts the intervals or drops
	// ticks to make up for slow receiver.
	// https://golang.org/pkg/time/#NewTicker
	// To pull latest root certs from SKS
	rootCertsTicker = time.NewTicker(time.Duration(configuration.ConfigurationInstance().RootCertsFetchInterval)*time.Second)
	// To pull current signing credentials - x5u and privatekey
	signingCredentialsTicker = time.NewTicker(time.Duration(configuration.ConfigurationInstance().SigningCredentialsFetchInterval)*time.Second)
	// To check on changes to sks URL or token
	sksSticrTicker = time.NewTicker(time.Duration(configuration.ConfigurationInstance().SksSticrFilesCheckInterval)*time.Second)
	// initiatize channel of empty struct. send this empty struct to stop timer, close channel and exit go routine
	stopTicker = make(chan struct{})	
}

//
func main() {
	logInfo("Type=vesperStart, Message=Starting vesper .... ")
	stop := make(chan os.Signal, 1)
	signal.Ignore(syscall.SIGPIPE)
	signal.Notify(stop, os.Interrupt, syscall.SIGTERM)

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


	// start periodic timer
	go func() {
		for {
			select {
			case <- rootCertsTicker.C:	
				// fetch root cerst from SKS and replace cached ones
				rootCerts.FetchRootCertsFromSks()
			case <- signingCredentialsTicker.C:	
				// fetch current x5u and privatekey for signing. This will replace cached credentials
				signingCredentials.FetchSigningCredentialsFromSks()
			case <- sksSticrTicker.C:
				sksCredentials.UpdateSksCredentials()
				x5u.UpdateSticrHost()
			case <- stopTicker:
				// Stop turns off a ticker. After Stop, no more ticks will be sent.
				// Stop does not close the channel, to prevent a read from the channel succeeding incorrectly
				// https://golang.org/pkg/time/#Ticker.Stop
				logInfo("Type=ntMgrTimerStop, Message=stopping all tickers and closing channel before exiting")
				rootCertsTicker.Stop()
				signingCredentialsTicker.Stop()
				sksSticrTicker.Stop()
				return
			}
		}
	}()

	var srv http.Server
	// Start HTTPS server only if cert and key file exist
	if (len(strings.TrimSpace(configuration.ConfigurationInstance().SslCertFile)) > 0) && (len(strings.TrimSpace(configuration.ConfigurationInstance().SslKeyFile)) > 0) {
		go func() {
			logInfo("Type=vesperHttpsServiceStart, Message=Staring HTTPS service on port 443 ...")
			// Note: netstats -plnt shows a IPv6 TCP socket listening on ":443"
			//       but no IPv4 TCP socket. This is not an issue
			srv := &http.Server{Addr: ":443", Handler: handler}
			if err := srv.ListenAndServeTLS(configuration.ConfigurationInstance().SslCertFile, configuration.ConfigurationInstance().SslKeyFile); err != nil {
				logError("Type=vesperHttpServiceFailure, Message=Could not start serving service due to (error: %s)", err)
				errs <- err
			}
		}()
	} else {
		// Start HTTP server
	 	go func() {
			hostPort := "127.0.0.1:80"
			if configuration.ConfigurationInstance().HttpHostPort != "" {
				parts := strings.Split(configuration.ConfigurationInstance().HttpHostPort, ":")
				if len(parts) != 2 {
					logError("Type=vesperHostPortFormatError, Message=config file contains invalid host-port format (%v) - should be [host:port].... cannot start Vesper Service .... ", configuration.ConfigurationInstance().HttpHostPort)
					os.Exit(5)
				}				
				hostPort = configuration.ConfigurationInstance().HttpHostPort
			}
			logInfo("Type=vesperHttpServiceStart, Message=Staring HTTP service on port %v ...", hostPort)
			// Start the service.
			// Note: netstats -plnt shows a IPv6 TCP socket listening on user specified port
			//       but no IPv4 TCP socket. This is not an issue
			srv := &http.Server{Addr: hostPort, Handler: handler}
			if err := srv.ListenAndServe(); err != nil {
				logError("Type=vesperHttpServiceFailure, Message=Could not start serving service due to (error: %s)", err)
				errs <- err
			}
		 }()
	}

	// This will run forever until channel receives error
	select {
	case err := <-errs:
		logError("Type=vesperHttpServiceFailure, Message=Could not start service due to (error: %s)", err)
		logInfo("Type=vesperShutdown, Message=Shutting down vesper .... ")
	case <-stop:
		logInfo("Type=vesperShutdown, Message=Shutting down vesper .... ")
		// Pass a context with a timeout to tell a blocking function that it
		// should abandon its work after the timeout elapses.
		ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
		defer cancel()
		err := srv.Shutdown(ctx)
		if err != nil {
			logError("Type=vesperHttpServiceShutdownFailure, Message=Shutdown of http server error - %v", err)
			logInfo("Type=vesperStop, Message=vesper stopped but NOT gracefully")
		} else {
			logInfo("Type=vesperStop, Message=vesper gracefully stopped")
		}
	}
}
