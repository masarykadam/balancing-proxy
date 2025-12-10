package main

import (
	"bufio"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/joho/godotenv"
)

// Config represents the JSON configuration
type Config struct {
	ListenAddr string           `json:"listen_addr"`
	MaxRetries int              `json:"max_retries"`
	Upstreams  []UpstreamConfig `json:"upstreams"`
}

// UpstreamConfig represents an upstream proxy configuration
type UpstreamConfig struct {
	Name             string `json:"name"`
	Host             string `json:"host"`
	Port             int    `json:"port"`
	UsernameTemplate string `json:"username_template"`
	PasswordEnv      string `json:"password_env"`
	SessionTimeUnit  string `json:"session_time_unit"`  // "seconds" or "minutes"
	SessionTimeMax   int64  `json:"session_time_max"`   // max in provider's unit
}

// SessionInfo holds parsed session information from client
type SessionInfo struct {
	Country     string
	SessionTime int64 // in seconds
	SessionID   string
}

var config Config
var vpsPassword string

func main() {
	// Load .env file
	godotenv.Load()

	// Load configuration
	configPath := os.Getenv("CONFIG_PATH")
	if configPath == "" {
		configPath = "config.json"
	}

	if err := loadConfig(configPath); err != nil {
		log.Fatalf("Failed to load config: %v", err)
	}

	vpsPassword = os.Getenv("VPS_PASSWORD")
	if vpsPassword == "" {
		vpsPassword = "my_vps_password"
	}

	log.Printf("Starting Balancing Proxy Server")
	log.Printf("Listening on: %s", config.ListenAddr)
	log.Printf("Configured upstreams:")
	for i, upstream := range config.Upstreams {
		log.Printf("  [%d] %s - %s:%d", i, upstream.Name, upstream.Host, upstream.Port)
	}
	log.Printf("Max retries: %d", config.MaxRetries)

	server := &http.Server{
		Addr:    config.ListenAddr,
		Handler: http.HandlerFunc(handleProxy),
	}

	log.Fatal(server.ListenAndServe())
}

func loadConfig(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &config)
}

func handleProxy(w http.ResponseWriter, r *http.Request) {
	// Authenticate client
	sessionInfo, err := authenticateClient(r)
	if err != nil {
		log.Printf("Auth failed: %v", err)
		w.Header().Set("Proxy-Authenticate", "Basic realm=\"Proxy\"")
		http.Error(w, "Proxy Authentication Required", http.StatusProxyAuthRequired)
		return
	}

	log.Printf("Authenticated: country=%s, session_time=%ds, session=%s",
		sessionInfo.Country, sessionInfo.SessionTime, sessionInfo.SessionID)

	// Try upstreams with failover
	var lastErr error
	maxAttempts := min(config.MaxRetries+1, len(config.Upstreams))

	for attempt := 0; attempt < maxAttempts; attempt++ {
		upstream := config.Upstreams[attempt]

		log.Printf("Attempt %d: Using upstream '%s' (%s:%d)",
			attempt+1, upstream.Name, upstream.Host, upstream.Port)

		if r.Method == http.MethodConnect {
			lastErr = handleHTTPS(w, r, &upstream, sessionInfo)
		} else {
			lastErr = handleHTTP(w, r, &upstream, sessionInfo)
		}

		if lastErr == nil {
			return // Success
		}

		log.Printf("Upstream '%s' failed: %v", upstream.Name, lastErr)

		if attempt < maxAttempts-1 {
			log.Printf("Initiating failover to upstream '%s'", config.Upstreams[attempt+1].Name)
		}
	}

	log.Printf("All retry attempts exhausted (%d upstreams tried)", maxAttempts)
	http.Error(w, "Bad Gateway", http.StatusBadGateway)
}

func authenticateClient(r *http.Request) (*SessionInfo, error) {
	auth := r.Header.Get("Proxy-Authorization")
	if auth == "" {
		return nil, fmt.Errorf("missing Proxy-Authorization header")
	}

	if !strings.HasPrefix(auth, "Basic ") {
		return nil, fmt.Errorf("invalid auth scheme")
	}

	decoded, err := base64.StdEncoding.DecodeString(auth[6:])
	if err != nil {
		return nil, fmt.Errorf("invalid base64")
	}

	parts := strings.SplitN(string(decoded), ":", 2)
	if len(parts) != 2 {
		return nil, fmt.Errorf("invalid credential format")
	}

	username, password := parts[0], parts[1]

	if password != vpsPassword {
		return nil, fmt.Errorf("invalid password")
	}

	return parseUsername(username)
}

func parseUsername(username string) (*SessionInfo, error) {
	parts := strings.Split(username, "_")

	if len(parts) >= 3 {
		var sessionTime int64
		fmt.Sscanf(parts[1], "%d", &sessionTime)
		return &SessionInfo{
			Country:     strings.ToUpper(parts[0]),
			SessionTime: sessionTime,
			SessionID:   strings.Join(parts[2:], "_"),
		}, nil
	} else if len(parts) == 2 {
		return &SessionInfo{
			Country:     strings.ToUpper(parts[0]),
			SessionTime: 21600, // Default 6 hours
			SessionID:   parts[1],
		}, nil
	}

	return &SessionInfo{
		Country:     "US",
		SessionTime: 21600,
		SessionID:   username,
	}, nil
}

func buildUpstreamCredentials(upstream *UpstreamConfig, session *SessionInfo) string {
	// Convert session time to provider's unit
	sessionTime := session.SessionTime
	if upstream.SessionTimeUnit == "minutes" {
		sessionTime = sessionTime / 60
	}

	// Clamp to max
	if upstream.SessionTimeMax > 0 && sessionTime > upstream.SessionTimeMax {
		sessionTime = upstream.SessionTimeMax
	}

	// Build username from template
	username := upstream.UsernameTemplate
	username = strings.ReplaceAll(username, "{country}", strings.ToUpper(session.Country))
	username = strings.ReplaceAll(username, "{country_lower}", strings.ToLower(session.Country))
	username = strings.ReplaceAll(username, "{session}", session.SessionID)
	username = strings.ReplaceAll(username, "{session_time}", fmt.Sprintf("%d", sessionTime))

	// Get password from env
	password := os.Getenv(upstream.PasswordEnv)

	log.Printf("  -> user=%s", username)

	// Return URL-encoded credentials (user:pass)
	return url.QueryEscape(username) + ":" + url.QueryEscape(password)
}

func buildUpstreamAuth(upstream *UpstreamConfig, session *SessionInfo) string {
	creds := buildUpstreamCredentials(upstream, session)
	// Unescape for base64 encoding (HTTPS CONNECT uses base64)
	creds, _ = url.QueryUnescape(creds)
	return base64.StdEncoding.EncodeToString([]byte(creds))
}

func handleHTTP(w http.ResponseWriter, r *http.Request, upstream *UpstreamConfig, session *SessionInfo) error {
	// Build upstream credentials
	upstreamAuth := buildUpstreamCredentials(upstream, session)

	// Embed auth in proxy URL (Go's http.Transport expects this)
	proxyURL := fmt.Sprintf("http://%s@%s:%d", upstreamAuth, upstream.Host, upstream.Port)
	proxy, _ := url.Parse(proxyURL)

	transport := &http.Transport{
		Proxy: http.ProxyURL(proxy),
		DialContext: (&net.Dialer{
			Timeout:   10 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
		ResponseHeaderTimeout: 60 * time.Second,
	}

	client := &http.Client{
		Transport: transport,
		Timeout:   90 * time.Second,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Create new request
	outReq, err := http.NewRequest(r.Method, r.URL.String(), r.Body)
	if err != nil {
		return err
	}

	// Copy headers
	for key, values := range r.Header {
		if key == "Proxy-Authorization" || key == "Proxy-Connection" {
			continue
		}
		for _, value := range values {
			outReq.Header.Add(key, value)
		}
	}

	resp, err := client.Do(outReq)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	// Copy response headers
	for key, values := range resp.Header {
		for _, value := range values {
			w.Header().Add(key, value)
		}
	}

	w.WriteHeader(resp.StatusCode)
	n, _ := io.Copy(w, resp.Body)
	log.Printf("  -> Copied %d bytes to client", n)

	return nil
}

func handleHTTPS(w http.ResponseWriter, r *http.Request, upstream *UpstreamConfig, session *SessionInfo) error {
	// Connect to upstream proxy
	upstreamAddr := fmt.Sprintf("%s:%d", upstream.Host, upstream.Port)
	upstreamConn, err := net.DialTimeout("tcp", upstreamAddr, 10*time.Second)
	if err != nil {
		return fmt.Errorf("connect to upstream: %w", err)
	}

	// Send CONNECT request to upstream proxy
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\nProxy-Authorization: Basic %s\r\n\r\n",
		r.Host, r.Host, buildUpstreamAuth(upstream, session))

	upstreamConn.SetDeadline(time.Now().Add(30 * time.Second))
	_, err = upstreamConn.Write([]byte(connectReq))
	if err != nil {
		upstreamConn.Close()
		return fmt.Errorf("send CONNECT: %w", err)
	}

	// Read response from upstream proxy
	br := bufio.NewReader(upstreamConn)
	resp, err := http.ReadResponse(br, nil)
	if err != nil {
		upstreamConn.Close()
		return fmt.Errorf("read CONNECT response: %w", err)
	}
	resp.Body.Close() // Must close even if empty

	if resp.StatusCode != http.StatusOK {
		upstreamConn.Close()
		return fmt.Errorf("upstream CONNECT failed: %d", resp.StatusCode)
	}

	// Hijack client connection
	hijacker, ok := w.(http.Hijacker)
	if !ok {
		upstreamConn.Close()
		return fmt.Errorf("hijacking not supported")
	}

	clientConn, _, err := hijacker.Hijack()
	if err != nil {
		upstreamConn.Close()
		return fmt.Errorf("hijack: %w", err)
	}

	// Send 200 OK to client
	clientConn.Write([]byte("HTTP/1.1 200 Connection Established\r\n\r\n"))

	// Clear deadlines for tunneling
	upstreamConn.SetDeadline(time.Time{})
	clientConn.SetDeadline(time.Time{})

	// Bridge connections
	go func() {
		io.Copy(upstreamConn, clientConn)
		upstreamConn.Close()
	}()
	go func() {
		io.Copy(clientConn, upstreamConn)
		clientConn.Close()
	}()

	return nil
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}
