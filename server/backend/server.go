package backend

import (
	"fmt"
	"log"
	"net/http"
	"roxy/server/config"
	"roxy/server/user"
)

var (
	cfg    *config.Config
	logger *log.Logger
)

func registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/status", statusHandler)
}

func StartServer(config *config.Config, logInstance *log.Logger) {
	cfg = config
	logger = logInstance
	mux := http.NewServeMux()
	registerRoutes(mux)
	server := &http.Server{
		Addr:    fmt.Sprintf(":%d", cfg.Port),
		Handler: mux,
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

func statusHandler(w http.ResponseWriter, r *http.Request) {
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Server is running"))
}

func SignUpHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	username := r.FormValue("username")
	password := r.FormValue("password")
	if username == "" || password == "" {
		http.Error(w, "Username and password are required", http.StatusBadRequest)
		return
	}

	// Check if user already exists
	_, exists := user.GetUser(username)
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
