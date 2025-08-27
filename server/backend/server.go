package backend

import (
	"fmt"
	"log"
	"net/http"
	"roxy/server/config"
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
