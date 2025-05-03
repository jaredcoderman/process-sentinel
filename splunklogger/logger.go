package splunklogger

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/joho/godotenv"
)

type SplunkEvent struct {
	Event  interface{} `json:"event"`
	Time   int64       `json:"time"`
	Source string      `json:"source"`
}

var (
	splunkToken string
	splunkURL   string
)

var insecureClient = &http.Client{
	Transport: &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true},
	},
}

func init() {
	_ = godotenv.Load()

	splunkToken = os.Getenv("SPLUNK_TOKEN")
	splunkURL = os.Getenv("SPLUNK_URL")

	if splunkToken == "" || splunkURL == "" {
		fmt.Println("⚠️  Missing SPLUNK_TOKEN or SPLUNK_URL in .env")
	}
}

func SendToSplunk(data interface{}) error {
	event := SplunkEvent{
		Event:  data,
		Time:   time.Now().Unix(),
		Source: "process-sentinel",
	}

	payload, err := json.Marshal(event)
	if err != nil {
		return fmt.Errorf("marshal error: %v", err)
	}

	req, err := http.NewRequest("POST", splunkURL, bytes.NewBuffer(payload))
	if err != nil {
		return fmt.Errorf("request error: %v", err)
	}

	req.Header.Set("Authorization", "Splunk "+splunkToken)
	req.Header.Set("Content-Type", "application/json")

	resp, err := insecureClient.Do(req)
	if err != nil {
		return fmt.Errorf("HTTP error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != 200 {
		return fmt.Errorf("splunk returned status: %v", resp.Status)
	}

	return nil
}
