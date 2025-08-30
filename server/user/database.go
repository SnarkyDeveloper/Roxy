package user

import (
	"crypto/rand"
	"database/sql"
	"encoding/base64"
	"fmt"
	"log"
	"roxy/server/config"
	"time"

	_ "github.com/glebarez/go-sqlite"
)

var (
	newUserCache = map[string]User{}
	userCache    = map[string]User{}
	sqliteDB     *sql.DB
	logger       *log.Logger
)

func setupTTL(conf *config.Config) {
	// push to db every ttl seconds
	sqlDB, err := sql.Open("sqlite", conf.Database.DBFile)
	if err != nil {
		log.Panicln("Failed to open user db:" + err.Error())
	}
	_, err = sqlDB.Exec("CREATE TABLE IF NOT EXISTS users (username TEXT, password TEXT, user_id TEXT PRIMARY KEY, token TEXT)")
	if err != nil {
		log.Panicln("Failed to create user table:" + err.Error())
	}
	sqliteDB = sqlDB
	ticker := time.NewTicker(time.Duration(conf.Database.TTL) * time.Second)
	go func() {
		for range ticker.C {
			if sqliteDB == nil {
				log.Panicln("DB not initialized")
			}

			for _, user := range newUserCache {
				_, err := sqliteDB.Exec("INSERT OR REPLACE INTO users (username, password, user_id, token) VALUES (?, ?, ?, ?)", user.Username, user.Password, user.UserID, user.Token)
				if err != nil {
					log.Panicln("Failed to insert user:" + err.Error())
				}
				delete(newUserCache, user.UserID)
			}
		}
	}()
}

func InitDB(conf *config.Config, logInstance *log.Logger) {
	logger = logInstance
	setupTTL(conf)
}

func AddUser(user User) {
	hashedUser := hashUser(user)
	newUserCache[user.UserID] = hashedUser // key by user_id
	if sqliteDB == nil {
		log.Panicln("DB not initialized")
	}
	userCache[user.UserID] = hashedUser
}

func GetUserId(username string) (string, bool) {
	if userCache[username].UserID != "" {
		return userCache[username].UserID, true
	}
	if sqliteDB == nil {
		log.Panicln("DB not initialized")
	}
	var userID string
	sqliteDB.QueryRow("SELECT user_id FROM users WHERE username = ?", username).Scan(&userID)
	return userID, userID != ""
}

// GetUser now takes user_id instead of username
func GetUser(userID string) (User, bool) { // bool = exists
	user, ok := userCache[userID]
	if ok {
		return user, ok
	}
	if sqliteDB == nil {
		log.Panicln("DB not initialized")
	}
	var u User
	err := sqliteDB.QueryRow("SELECT username, password, user_id, token FROM users WHERE user_id = ?", userID).
		Scan(&u.Username, &u.Password, &u.UserID, &u.Token)
	if err != nil {
		return User{}, false
	}
	userCache[userID] = u
	return u, true
}

// RemoveUser now takes user_id instead of username
func RemoveUser(userID string) {
	delete(userCache, userID)
	if sqliteDB == nil {
		log.Panicln("DB not initialized")
	}
	sqliteDB.Exec("DELETE FROM users WHERE user_id = ?", userID)
}

// CheckUser now takes user_id and password
func CheckUser(userID, password string) bool {
	user, ok := GetUser(userID)
	if !ok {
		return false
	}
	return user.Password == password
}

func GenID() string {
	var b [16]byte // 128 bit
	_, err := rand.Read(b[:])
	if err != nil {
		return fmt.Sprintf("%d", time.Now().UnixNano())
	}
	return fmt.Sprintf("%x", b[:])
}

func GenToken(id string) (string, error) {
	length := 16
	b := make([]byte, length)
	_, err := rand.Read(b)
	if err != nil {
		return "", err
	}
	tokenStr := id + ":" + base64.URLEncoding.EncodeToString(b)
	return base64.URLEncoding.EncodeToString([]byte(tokenStr)), nil
}

func ValidateToken(token string) bool {
	if token == "" {
		return false
	}
	if sqliteDB == nil {
		log.Panicln("DB not initialized")
	}

	var userID string
	sqliteDB.QueryRow("SELECT user_id FROM users WHERE token = ?", token).Scan(&userID)
	if userID == "" {
		return false
	}
	u, _ := GetUser(userID)
	return u.Token == token
}
