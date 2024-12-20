package main

import (
	"embed"
	"fmt"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os/exec"
	"runtime"

	"github.com/gorilla/websocket"
)

//go:embed static/*
var staticFiles embed.FS

// Message represents the WebSocket message structure
type Message struct {
	Type    string `json:"type"`
	Content string `json:"content"`
}

var allowedOrigins = []string{"http://localhost"}

func isOriginAllowed(r *http.Request) bool {
	origin := r.Header.Get("Origin")
	fmt.Printf("origin: %s\n", origin)
	for _, allowedOrigin := range allowedOrigins {
		if origin == allowedOrigin {
			return true
		}
	}
	return false
}

var upgrader websocket.Upgrader

func GetUpgrader(httpPort int) *websocket.Upgrader {
	return &websocket.Upgrader{
		ReadBufferSize:  1024,
		WriteBufferSize: 1024,
		CheckOrigin:     fnOriginCheck(httpPort),
	}
}

func fnOriginCheck(httpPort int) func(r *http.Request) bool {
	return func(r *http.Request) bool {
		origin := r.Header.Get("Origin")
		fmt.Printf("origin: %s\n", origin)
		if origin == fmt.Sprintf("http://localhost:%d", httpPort) {
			return true
		}
		return false
	}
}

func main() {
	// Get HTTP port
	httpPort, err := getAvailablePort()
	if err != nil {
		fmt.Printf("failed to get http available port: %v\n", err)
		return
	}

	// Get websocket port
	wsPort, err := getAvailablePort()
	if err != nil {
		fmt.Printf("failed to get ws available port: %v\n", err)
		return
	}

	// Print the available ports
	fmt.Printf("http port: %d\n", httpPort)
	fmt.Printf("ws port: %d\n", wsPort)

	// initialize the upgrader
	upgrader = *GetUpgrader(httpPort)

	// Serve files from sub directory static rooted at static
	staticContent, err := fs.Sub(staticFiles, "static")
	if err != nil {
		fmt.Printf("failed to get static content: %v\n", err)
		return
	}

	// Create a http server
	httpServer := &http.Server{
		Addr: fmt.Sprintf("localhost:%d", httpPort),
		Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {

			// Add headers for WebSocket port
			if r.URL.Path == "/" {
				w.Header().Set("X-Websocket-Port", fmt.Sprintf("%d", wsPort))
				fmt.Printf("%s header X-Websocket-Port: %d\n", r.URL.Path, wsPort)
			}

			// Serve static content
			http.FileServer(http.FS(staticContent)).ServeHTTP(w, r)
		}),
	}

	// create a websocket server
	wsServer := &http.Server{
		Addr:    fmt.Sprintf("localhost:%d", wsPort),
		Handler: http.HandlerFunc(handleWebsocket),
	}

	// Start websocket server
	go func() {
		log.Printf("Starting websocket server on port %d\n", wsPort)
		if err := wsServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("failed to start websocket server: %v\n", err)
		}
	}()

	// Start http server
	go func() {
		log.Printf("Starting http server on port %d\n", httpPort)
		if err := httpServer.ListenAndServe(); err != http.ErrServerClosed {
			fmt.Printf("failed to start http server: %v\n", err)
		}
	}()

	// Open Browser
	url := fmt.Sprintf("http://localhost:%d", httpPort)
	log.Printf("opening browser at %s\n", url)
	if err = openBrowser(url); err != nil {
		fmt.Printf("failed to open browser: %v\n", err)
	}

	// Keep the application running Wait forever
	select {}
}

// handle websocket connections
func handleWebsocket(w http.ResponseWriter, r *http.Request) {
	// Upgrade connection to websocket
	conn, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		fmt.Printf("failed to upgrade connection to websocket: %v\n", err)
		return
	}
	defer conn.Close()

	// Send Initial Message
	if err := conn.WriteJSON(Message{Type: "connected", Content: "Websocket connection established"}); err != nil {
		fmt.Printf("failed to write initial message to websocket: %v\n", err)
		return
	}

	// Message loop
	for {
		// Read message from the websocket
		var receivedMsg Message
		err := conn.ReadJSON(&receivedMsg)
		if err != nil {
			if !websocket.IsCloseError(err, websocket.CloseNormalClosure, websocket.CloseGoingAway) {
				fmt.Printf("failed to read message from websocket: %v\n", err)
			}
			break
		}

		// Print the message
		fmt.Printf("message received: %+v\n", receivedMsg)

		// Write message back to the websocket
		response := Message{Type: "response", Content: fmt.Sprintf("Message received %s", receivedMsg.Content)}

		err = conn.WriteJSON(response)
		if err != nil {
			fmt.Printf("failed to write message to websocket: %v\n", err)
			break
		}
	}
}

// Get available port on the system
func getAvailablePort() (int, error) {

	// Resolve TCP address; what does localhost:0 mean?
	// localhost:0 means that the system will choose an available port
	addr, err := net.ResolveTCPAddr("tcp", "localhost:0")
	if err != nil {
		return 0, fmt.Errorf("failed to resolve tcp address: %v", err)
	}

	// Listen on TCP address
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, fmt.Errorf("failed to listen on tcp address: %v", err)
	}
	defer l.Close()

	// Return the port number
	return l.Addr().(*net.TCPAddr).Port, nil
}

// Open Web Browser
func openBrowser(url string) error {
	// Open the browser
	// return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
	// return exec.Command("cmd", "/c", "start", url).Start()
	// use switch on runtime.GOOS to support multiple platforms

	switch runtime.GOOS {
	case "linux":
		return exec.Command("xdg-open", url).Start()
	case "windows":
		return exec.Command("rundll32", "url.dll,FileProtocolHandler", url).Start()
		// 	return exec.Command("cmd", "/c", "start", url).Start()
	case "darwin":
		return exec.Command("open", url).Start()
	default:
		return fmt.Errorf("unsupported platform")
	}
}
