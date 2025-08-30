package backend

import (
	"fmt"
	"log"
	"net/http"
	"roxy/server/config"
	"roxy/server/user"
	"slices"
)

var (
	cfg    *config.Config
	logger *log.Logger
)

func allowedMethods(allowed interface{}, w http.ResponseWriter, r *http.Request) bool {
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

func AuthMiddleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		valid := user.ValidateToken(token)
		if !valid {
			http.Error(w, "Invalid or expired token", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func registerRoutes(mux *http.ServeMux) {
	mux.HandleFunc("/signup", SignUpHandler)
	mux.HandleFunc("/signin", SignInHandler)
	mux.HandleFunc("/status", statusHandler)
	mux.Handle("/protected", AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("You have accessed a protected route"))
	})))

	logger.Println("All routes registered and server started on port", cfg.Port)
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

func SignInHandler(w http.ResponseWriter, r *http.Request) {
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
	if !user.CheckUser(username, password) {
		http.Error(w, "Invalid username or password", http.StatusUnauthorized)
		return
	}
	u, _ := user.GetUser(username)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte(`{"message":"Sign-in successful","token":"` + u.Token + `"}`))
}
