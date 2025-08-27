package user

import (
	"crypto/rand"
	"encoding/base64"
	"fmt"
	_ "github.com/glebarez/go-sqlite"
	"roxy/server/config"
	"time"
)

type User struct {
	Username string `json:"username"`
	Password string `json:"password"` // hash. Secure for in mem use
	UserID   string `json:"user_id"`
}

var userCache = map[string]User{}

func setupTTL(conf *config.Config) {
	// push to db every ttl seconds
	ticker := time.NewTicker(time.Duration(conf.Database.TTL) * time.Second)

	go func() {
		for range ticker.C {
			// push to db
			
		}
	}()

}

func AddUser(user User) {
	userCache[user.Username] = user
}

func genID() string {
	var b [16]byte // 128 bit
	_, err := rand.Read(b[:])
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b[:])
}
func genToken(id string) (string, error) {
	length := 16
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	tokenStr := id + ":" + base64.URLEncoding.EncodeToString(b)
	return base64.URLEncoding.EncodeToString([]byte(tokenStr)), nil
}
