package main

import (
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"github.com/sirupsen/logrus"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"runtime"
	"time"
)

func main() {
	flagSet := flag.NewFlagSet("spiffe-user-demo", flag.ContinueOnError)

	socketPath := flagSet.String("socketPath", "", "Socket path on which to listen for connections. Will use the SPIFFE_ENDPOINT_SOCKET environment variable if not set. Will otherwise use \"/tmp/agent.sock\" by default.")
	logLevel := flagSet.String("logLevel", "INFO", "Log verbosity level. One of: TRACE, DEBUG, INFO, WARN, ERROR, FATAL, PANIC")
	refreshFrequency := flagSet.String("refreshFrequency", "1h", "Frequency with which certificates should be refreshed.")
	var serviceHost string
	flagSet.StringVar(&serviceHost, "hostname", "https://spiffe-user-demo.herokuapp.com", "The hostname of the service to login to and retrieve SVIDs from.")

	err := flagSet.Parse(os.Args[1:])
	if err != nil {
		fmt.Printf("Failed to parse flags: %v", err)
		os.Exit(1)
	}

	var level logrus.Level
	switch *logLevel {
	case "TRACE":
		level = logrus.TraceLevel
	case "DEBUG":
		level = logrus.DebugLevel
	case "INFO":
		level = logrus.InfoLevel
	case "WARN":
		level = logrus.WarnLevel
	case "ERROR":
		level = logrus.ErrorLevel
	case "FATAL":
		level = logrus.FatalLevel
	case "PANIC":
		level = logrus.PanicLevel
	default:
		fmt.Printf("Invalid logLevel flag: %s\n", *logLevel)
		os.Exit(1)
	}

	refreshFrequencyD, err := time.ParseDuration(*refreshFrequency)
	if err != nil {
		fmt.Printf("Invalid refresh frequency \"%s\": %v\n", *refreshFrequency, err)
		os.Exit(1)
	}

	if *socketPath == "" {
		*socketPath = os.Getenv("SPIFFE_ENDPOINT_SOCKET")
		if *socketPath == "" {
			*socketPath = "/tmp/agent.sock"
		}
	}

	logger := logrus.New()
	logger.Level = level

	authToken, err := bootstrapLogin(serviceHost, logger)
	if err != nil {
		fmt.Printf("Failed to bootstrap login: %v\n", err)
		os.Exit(1)
	}

	logger.Info("Authentication successful. Starting workload agent.")
	s, err := StartWorkloadServiceServer(&WorkloadServiceServerOptions{
		RefreshFrequency: refreshFrequencyD,
		SocketPath:       *socketPath,
		Logger:           logger,
		Client: &UserClientImpl{
			AuthToken: authToken,
			Hostname:  serviceHost,
		},
	})
	if err != nil {
		logger.Fatalf("Failed to initialize server: %v\n", err)
	}

	// Ask the server to stop and gracefully shutdown on a Ctrl+C signal
	go func() {
		signalCh := make(chan os.Signal, 1)
		signal.Notify(signalCh, os.Interrupt)
		<-signalCh

		s.Stop()
	}()

	err = s.Wait()
	if err != nil {
		logger.Errorf("Got error waiting for server to shutdown")
	} else {
		logger.Info("Shutdown gracefully.")
	}
}

func bootstrapLogin(serviceHost string, logger *logrus.Logger) (string, error) {
	lis, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", fmt.Errorf("failed to start http callback listener: %v", err)
	}
	defer lis.Close()

	var authToken string
	doneChan := make(chan bool)
	defer close(doneChan)
	go http.Serve(lis, http.HandlerFunc(func(writer http.ResponseWriter, req *http.Request) {
		if origin := req.Header.Get("Origin"); origin != "" {
			if origin != serviceHost {
				http.Error(writer, "Invalid origin: "+origin, http.StatusBadRequest)
				return
			}
			writer.Header().Add("Access-Control-Allow-Origin", origin)
			writer.Header().Add("Access-Control-Allow-Methods", "OPTIONS, POST")
			writer.Header().Add("Access-Control-Allow-Headers", "Content-Type")
		}
		if req.Method == http.MethodOptions {
			return
		}

		var postBody struct {
			AuthToken string `json:"authToken"`
		}
		err = json.NewDecoder(req.Body).Decode(&postBody)
		if err != nil {
			http.Error(writer, err.Error(), http.StatusBadRequest)
		} else {
			authToken = postBody.AuthToken
		}
		doneChan <- true
	}))

	url := fmt.Sprintf("%s/login?callback=%d\n", serviceHost, lis.Addr().(*net.TCPAddr).Port)
	fmt.Printf("Browse to: %s", url)
	err = openbrowser(url)
	if err != nil {
		logger.Warnf("Failed to automatically open browser: %v", err)
	}

	// Wait until callback is done or timeout is reached
	timer := time.NewTimer(1 * time.Minute)
	defer timer.Stop()
	select {
	case <-timer.C:
	case <-doneChan:
	}

	if authToken == "" {
		return "", errors.New("timeout reached waiting for login")
	}
	return authToken, nil
}

func openbrowser(url string) error {
	var err error

	switch runtime.GOOS {
	case "linux":
		err = exec.Command("xdg-open", url).Start()
	case "windows":
		err = exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	case "darwin":
		err = exec.Command("open", url).Start()
	default:
		err = fmt.Errorf("unsupported platform")
	}
	if err != nil {
		return err
	}
	return nil
}
