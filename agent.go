package main

import (
	"bytes"
	"crypto/tls"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"math/rand"
	"net/http"
	"strings"
	"text/template"
	"time"

	"github.com/google/uuid"
)

type Agent struct {
	ServerAddress string
	EnrollSecret  string
	NodeKey       string
	UUID          string
	Client        http.Client
	Templates     *template.Template
	strings       map[string]string
}

func NewAgent(serverAddress, enrollSecret string, templates *template.Template) *Agent {
	transport := http.DefaultTransport.(*http.Transport).Clone()
	transport.TLSClientConfig = &tls.Config{InsecureSkipVerify: true}
	transport.DisableCompression = true
	return &Agent{
		ServerAddress: serverAddress,
		EnrollSecret:  enrollSecret,
		Templates:     templates,
		UUID:          uuid.New().String(),
		Client:        http.Client{Transport: transport},
		strings:       make(map[string]string),
	}
}

type enrollResponse struct {
	NodeKey string `json:"node_key"`
}

func (a *Agent) runLoop() {
	a.Enroll()
	for {
		a.Config()
		a.DistributedRead()
		a.DistributedWrite()
		time.Sleep(10 * time.Second)
	}
}

const stringVals = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_."

func (a *Agent) randomString(n int) string {
	sb := strings.Builder{}
	sb.Grow(n)
	for i := 0; i < n; i++ {
		sb.WriteByte(stringVals[rand.Int63()%int64(len(stringVals))])
	}
	return sb.String()
}

func (a *Agent) CachedString(key string) string {
	if val, ok := a.strings[key]; ok {
		return val
	}
	val := a.randomString(12)
	a.strings[key] = val
	return val
}

func (a *Agent) Enroll() {
	var body bytes.Buffer
	a.Templates.ExecuteTemplate(&body, "enroll", a)

	req, err := http.NewRequest("POST", a.ServerAddress+"/api/v1/osquery/enroll", &body)
	if err != nil {
		log.Println("create request:", err)
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", "osquery/4.1.2")

	resp, err := a.Client.Do(req)
	if err != nil {
		log.Println("do request:", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Println("status:", resp.Status)
		return
	}

	var parsedResp enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&parsedResp); err != nil {
		log.Println("json parse:", err)
		return
	}

	a.NodeKey = parsedResp.NodeKey
}

func (a *Agent) Config() {
	body := bytes.NewBufferString(`{"node_key": "` + a.NodeKey + `"}`)

	req, err := http.NewRequest("POST", a.ServerAddress+"/api/v1/osquery/config", body)
	if err != nil {
		log.Println("create config request:", err)
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", "osquery/4.1.2")

	resp, err := a.Client.Do(req)
	if err != nil {
		log.Println("do config request:", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Println("config status:", resp.Status)
		return
	}

	// No need to read the config body
}

func (a *Agent) DistributedRead() {
	body := bytes.NewBufferString(`{"node_key": "` + a.NodeKey + `"}`)

	req, err := http.NewRequest("POST", a.ServerAddress+"/api/v1/osquery/distributed/read", body)
	if err != nil {
		log.Println("create distributed read request:", err)
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", "osquery/4.1.2")

	resp, err := a.Client.Do(req)
	if err != nil {
		log.Println("do distributed read request:", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Println("distributed read status:", resp.Status)
		return
	}

	// No need to read the distributed read body (for now)
}

func (a *Agent) DistributedWrite() {
	var body bytes.Buffer
	a.Templates.ExecuteTemplate(&body, "distributed_write", a)

	req, err := http.NewRequest("POST", a.ServerAddress+"/api/v1/osquery/distributed/write", &body)
	if err != nil {
		log.Println("create distributed write request:", err)
		return
	}
	req.Header.Add("Content-Type", "application/json")
	req.Header.Add("Accept", "application/json")
	req.Header.Add("User-Agent", "osquery/4.1.2")

	resp, err := a.Client.Do(req)
	if err != nil {
		log.Println("do distributed write request:", err)
		return
	}

	if resp.StatusCode != http.StatusOK {
		log.Println("distributed write status:", resp.Status)
		return
	}

	// No need to read the distributed write body
}

func main() {
	serverURL := flag.String("server_url", "https://localhost:8080", "URL (with protocol and port of osquery server)")
	enrollSecret := flag.String("enroll_secret", "", "Enroll secret to authenticate enrollment")
	hostCount := flag.Int("host_count", 10, "Number of hosts to start (default 10)")
	randSeed := flag.Int64("seed", time.Now().UnixNano(), "Seed for random generator (default current time)")

	flag.Parse()

	rand.Seed(*randSeed)

	tmpl, err := template.ParseGlob("*.tmpl")
	if err != nil {
		log.Fatal("parse templates: ", err)
	}

	// Spread requests over the 10 seconds interval
	sleepTime := (10 * time.Second) / time.Duration(*hostCount)
	var agents []*Agent
	for i := 0; i < *hostCount; i++ {
		a := NewAgent(*serverURL, *enrollSecret, tmpl)
		agents = append(agents, a)
		go a.runLoop()
		time.Sleep(sleepTime)
	}

	fmt.Println("Agents running. Kill with C-c.")
	<-make(chan struct{})
}
