package backend

import (
	"bufio"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"log"
	"net/http"
	"net/http/httputil"

	"golang.org/x/net/websocket"

	"roxy/server/config"
	"roxy/server/helpers"
	"roxy/server/user"
	"slices"

	"github.com/julienschmidt/httprouter"
)

type Connection struct {
	WS        *websocket.Conn // conn to send req to
	UserID    string          // which user?
	Path      string          // ie: /:username/:repo (for lookup from request path)
	ForwardTo string          // ie: localhost:8000
}

// mockConn implements io.Reader for respBytes
type mockConn struct {
	data   []byte
	offset int
}

func (m *mockConn) Read(p []byte) (n int, err error) {
	if m.offset >= len(m.data) {
		return 0, io.EOF
	}
	n = copy(p, m.data[m.offset:])
	m.offset += n
	return n, nil
}

var (
	cfg              *config.Config
	logger           *log.Logger
	connectedClients = make(map[string][]*Connection) // userID -> list of all active connections
)

func allowedMethods(allowed any, w http.ResponseWriter, r *http.Request) bool {
	var methods []string
	switch v := allowed.(type) {
	case string:
		methods = []string{v}
	case []string:
		methods = v
	default:
		http.Error(w, "Method not allowed", http.StatusInternalServerError)
		return false
	}
	if slices.Contains(methods, r.Method) {
		return true
	}
	http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	return false // Stop further processing
}

func registerRoutes(router *httprouter.Router) {
	router.POST("/signup", signUpHandler)
	router.POST("/login", signInHandler)
	router.GET("/status", statusHandler)
	router.GET("/share", func(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
		websocket.Handler(startShare).ServeHTTP(w, r)
	})

	logger.Println("All routes registered and server started on port", cfg.Port)
}

func StartServer(config *config.Config, logInstance *log.Logger) {
	cfg = config
	logger = logInstance
	router := httprouter.New()
	registerRoutes(router)
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: router,
	}

	logger.Fatal(server.ListenAndServe())
}

func GetPath() string {
	return cfg.Path
}

func HandleError(err error) {
	if err != nil {
		logger.Println("Error:", err)
	}
}

func statusHandler(w http.ResponseWriter, _ *http.Request, _ httprouter.Params) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Server is running"))
}

func signUpHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if !allowedMethods(http.MethodPost, w, r) {
		return
	}
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// does exist
	_, exists := user.GetUserId(username)
	if exists {
		http.Error(w, "User already exists", http.StatusConflict)
		return
	}

	userID := user.GenID()
	token, err := user.GenToken(userID)
	if err != nil {
		http.Error(w, "Failed to generate token", http.StatusInternalServerError)
		return
	}
	newUser := user.User{
		Username: username,
		Password: password,
		UserID:   userID,
		Token:    token,
	}
	user.AddUser(newUser)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	w.Write([]byte(`{"message":"User created successfully","token":"` + token + `"}`))
}

func signInHandler(w http.ResponseWriter, r *http.Request, _ httprouter.Params) {
	if !allowedMethods(http.MethodPost, w, r) {
		return
	}
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}
	userId, ok := user.GetUserId(username)
	if !ok {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	if !user.CheckUser(userId, password) {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	u, _ := user.GetUser(userId)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Sign-in successful","token":"` + u.Token + `"}`))
}

// Actual reverse proxy websocket server

type Message struct {
	Msg       string `json:"msg,omitempty"`
	Count     int    `json:"count,omitempty"`
	Token     string `json:"token,omitempty"`
	ForwardTo string `json:"forwardTo,omitempty"`
	Repo      struct {
		Name string `json:"name,omitempty"`
		ID   string `json:"id,omitempty"`
	} `json:"repo"`
}

// Example auth pass: {"token": "MzY..."}
func startShare(ws *websocket.Conn) {
	if cfg == nil {
		logger.Println("Config not initialized")
		ws.Close()
		return
	}
	defer func() {
		// Remove ws from connectedClients
		for userID, conns := range connectedClients {
			for i, conn := range conns {
				if conn.WS == ws {
					connectedClients[userID] = append(conns[:i], conns[i+1:]...)
					break
				}
			}
			if len(connectedClients[userID]) == 0 {
				delete(connectedClients, userID)
			}
		}
		ws.Close()
	}()
	var msg Message
	for {
		err := websocket.JSON.Receive(ws, &msg)
		if err != nil {
			logger.Println("WebSocket receive error:", err)
			break
		}
		if msg.Count > 1 { // auth
			if !user.ValidateToken(msg.Token) {
				websocket.JSON.Send(ws, Message{Msg: "Unauthorized"})
				ws.Close()
				break
			}
			userID, err := user.GetIDFromToken(msg.Token)
			if err != nil {
				websocket.JSON.Send(ws, Message{Msg: "Unauthorized"})
				ws.Close()
				break
			}
			u, ok := user.GetUser(userID)
			if !ok {
				websocket.JSON.Send(ws, Message{Msg: "Unauthorized"})
				ws.Close()
				break
			}
			connection := Connection{
				WS:        ws,
				UserID:    userID,
				Path:      helpers.CreatePath(cfg, u, config.Repo{Name: msg.Repo.Name, ID: msg.Repo.ID}),
				ForwardTo: msg.ForwardTo,
			}
			connectedClients[userID] = append(connectedClients[userID], &connection)
			websocket.JSON.Send(ws, Message{Msg: "Authorized"})
		} else if msg.Msg == "ping" {
			msg.Msg = "pong"
			websocket.JSON.Send(ws, msg)
		}
	}
}

func handleExternReq(w http.ResponseWriter, r *http.Request, ps httprouter.Params) {
	var isValid bool
	var connection *Connection
	for _, v := range connectedClients {
		path := r.URL.Path
		for _, c := range v {
			isValid = c.Path == path
			if isValid {
				connection = c
				break
			}
		}
	}
	if !isValid {
		http.Error(w, "You may have visited the wrong page. Please try again", http.StatusNotFound)
		return
	}

	clientIP := r.RemoteAddr
	if clientIP != r.Header.Get("X-Forwarded-For") {
		r.Header.Set("X-Forwarded-For", clientIP) // Set the client IP in the header to be dumped to ws
	}

	nonceBytes := make([]byte, 16)
	_, err := rand.Read(nonceBytes)
	if err != nil {
		http.Error(w, "Internal server error", http.StatusInternalServerError)
		return
	}
	nonce := base64.URLEncoding.EncodeToString(nonceBytes)

	r.Header.Set("ROXY-WS-NONCE", nonce) // for verification of request to relay response
	// dump request to ws

	// convert r to bytes using httputil
	reqBytes, err := httputil.DumpRequest(r, true)
	if err != nil {
		http.Error(w, "Failed to process request", http.StatusInternalServerError)
		return
	}
	err = websocket.Message.Send(connection.WS, reqBytes)
	if err != nil {
		http.Error(w, "Failed to process request", http.StatusInternalServerError)
		return
	}
	// wait for response with same nonce
	var respBytes []byte
	for {
		err = websocket.Message.Receive(connection.WS, &respBytes)
		if err != nil {
			http.Error(w, "Failed to receive response", http.StatusInternalServerError)
			return
		}
		// check if nonce matches
		if len(respBytes) < 100 { // arbitrary small size to filter out non-responses
			continue
		}
		resp, err := http.ReadResponse(bufio.NewReader(httputil.NewChunkedReader(&mockConn{data: respBytes})), r)
		if err != nil {
			continue
		}
		if resp.Header.Get("ROXY-WS-NONCE") == nonce {
			for k, v := range resp.Header {
				for _, vv := range v {
					w.Header().Add(k, vv)
				}
			}
			w.WriteHeader(resp.StatusCode)
			bodyBytes, err := io.ReadAll(resp.Body)
			if err != nil {
				http.Error(w, "Failed to read response body", http.StatusInternalServerError)
				resp.Body.Close()
				break
			}
			w.Write(bodyBytes)
			resp.Body.Close()
			break
		}
	}
}
