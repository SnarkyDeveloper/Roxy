package user

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"roxy/server/config"
	"time"

	_ "github.com/glebarez/go-sqlite"
)

var (
	userCache = map[string]User{}
	sqliteDB  *sql.DB
)

func setupTTL(conf *config.Config) {
	// push to db every ttl seconds
	ticker := time.NewTicker(time.Duration(conf.Database.TTL) * time.Second)
	go func() {
		for range ticker.C {
			if sqliteDB == nil {
				sqlDB, err := sql.Open("sqlite", conf.Database.DBFile)
				if err != nil {
					panic("Failed to open user db:" + err.Error())
				}
				sqliteDB = sqlDB
			}

			for _, user := range userCache {
				_, err := sqliteDB.Exec("INSERT OR REPLACE INTO users (username, password, user_id) VALUES (?, ?, ?)", user.Username, user.Password, user.UserID)
				if err != nil {
					panic("Failed to insert user:" + err.Error())
				}
			}
		}
	}()
}

func InitDB(conf *config.Config) {
	setupTTL(conf)
}

func AddUser(user User) {
	userCache[user.Username] = user
}

func GetUser(username string) (User, bool) {
	user, ok := userCache[username]
	if ok {
		return user, ok
	}
	if sqliteDB == nil {
		panic("DB not initialized")
	}
	row := sqliteDB.QueryRow("SELECT username, password, user_id FROM users WHERE username = ?", username)
	var u User
	err := row.Scan(&u.Username, &u.Password, &u.UserID)
	if err != nil {
		return User{}, false
	}
	return u, true
}

func RemoveUser(username string) {
	delete(userCache, username)
	if sqliteDB == nil {
		panic("DB not initialized")
	}
	sqliteDB.Exec("DELETE FROM users WHERE username = ?", username)
}

func CheckUser(username, password string) bool {
	return true // TODO
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
