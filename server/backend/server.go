package backend

import (
	"fmt"
	"log"
	"net/http"

	"roxy/server/config"
	"roxy/server/user"
	"slices"

	"github.com/julienschmidt/httprouter"
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
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func registerRoutes(router *httprouter.Router) {
	router.POST("/signup", signUpHandler)
	router.POST("/login", signInHandler)
	router.GET("/status", statusHandler)
	router.Handler("GET", "/protected/:name", AuthMiddleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ps := httprouter.ParamsFromContext(r.Context())
		name := ps.ByName("name")
		w.Write([]byte("Hello, " + name + "! This is a protected route."))
	})))

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
