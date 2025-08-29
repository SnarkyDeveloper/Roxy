package main

import (
	"log"
	"os"
	"roxy/server/backend"
	"roxy/server/config"
	"roxy/server/user"
)

/*
	Roxy is a reverse proxy server written in Go.
	It is designed to handle HTTP and HTTPS requests, providing features such as load balancing, caching, and request routing.
	Outputs to <domain>/<username>/<repo>

	Config is in config.json
*/

func main() {
	// load cfg
	config, err := config.ParseConfig("config.yaml")
	if err != nil {
		panic(err)
	}
	logger := log.New(os.Stdout, "[ROXY] ", log.LstdFlags) // Output example: [ROXY] 2024/06/01 12:00:00 message
	user.InitDB(config, logger)
	backend.StartServer(config, logger)
}
