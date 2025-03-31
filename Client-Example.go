package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"strings"
	"time"
)

type Client struct {
	APIKey    string
	ServerURL string
}

type Embed struct {
	Title       string `json:"title"`
	Description string `json:"description"`
	Color       int    `json:"color"`
}

type RequestData struct {
	APIKey string  `json:"api_key"`
	Embeds []Embed `json:"embeds"`
	IP     string  `json:"ip"`
}

func NewClient(apiKey, serverURL string) *Client {
	return &Client{
		APIKey:    apiKey,
		ServerURL: serverURL,
	}
}

func (c *Client) GetLocalIP() string {
	resp, err := http.Get("http://api.ipify.org?format=text")
	if err != nil {
		fmt.Println("Error fetching external IP:", err)
		return ""
	}
	defer resp.Body.Close()

	ip, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading IP response:", err)
		return ""
	}

	return strings.TrimSpace(string(ip))
}

func (c *Client) SendMessage(message string) {
	ip := c.GetLocalIP()
	if ip == "" {
		return
	}

	embed := Embed{
		Title:       "Greeting from Go",
		Description: message,
		Color:       5620992,
	}

	requestData := RequestData{
		APIKey: c.APIKey,
		Embeds: []Embed{embed},
		IP:     ip,
	}

	jsonData, err := json.Marshal(requestData)
	if err != nil {
		fmt.Println("Error marshalling request data:", err)
		return
	}

	client := &http.Client{Timeout: 10 * time.Second}
	req, err := http.NewRequest("SIGMA", c.ServerURL, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println("Error creating request:", err)
		return
	}

	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("User-Agent", "Go-Client")

	resp, err := client.Do(req)
	if err != nil {
		fmt.Println("Error sending request:", err)
		return
	}
	defer resp.Body.Close()

	respBody, err := ioutil.ReadAll(resp.Body)
	if err != nil {
		fmt.Println("Error reading response:", err)
		return
	}

	fmt.Printf("Response %d: %s\n", resp.StatusCode, string(respBody))
}

func main() {
	client := NewClient("your-api-key", "http://localhost/index.php") // replace localhost with yours
	for {
		client.SendMessage("Hello, Discord!") // replace
		time.Sleep(5 * time.Second)
	}
}
