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
	_, err = sqlDB.Exec("CREATE TABLE IF NOT EXISTS users (username TEXT PRIMARY KEY, password TEXT, user_id TEXT, token TEXT)")
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
				_, err := sqliteDB.Exec("INSERT OR REPLACE INTO users (username, password, user_id) VALUES (?, ?, ?)", user.Username, user.Password, user.UserID, user.Token)
				if err != nil {
					log.Panicln("Failed to insert user:" + err.Error())
				}
				delete(newUserCache, user.Username)
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
	newUserCache[user.Username] = hashedUser // hash on cache add, not on every check
	if sqliteDB == nil {
		log.Panicln("DB not initialized")
	}
	userCache[user.Username] = hashedUser // if it doesn't fail
}

func GetUser(username string) (User, bool) { // bool = exists
	user, ok := userCache[username]
	logger.Println("GetUser:", username, "found in cache:", ok)
	if ok {
		return user, ok
	}
	if sqliteDB == nil {
		log.Panicln("DB not initialized")
	}
	var u User
	err := sqliteDB.QueryRow("SELECT username, password, user_id, token FROM users WHERE username = ?", username).
		Scan(&u.Username, &u.Password, &u.UserID, &u.Token)
	if err != nil {
		if err == sql.ErrNoRows {
			logger.Println("GetUser:", username, "not found in db")
		} else {
			logger.Println("GetUser:", username, "error querying db:", err)
		}
		return User{}, false
	}
	userCache[username] = u
	return u, true
}

func RemoveUser(username string) {
	delete(userCache, username)
	if sqliteDB == nil {
		log.Panicln("DB not initialized")
	}
	sqliteDB.Exec("DELETE FROM users WHERE username = ?", username)
}

func CheckUser(username, password string) bool {
	user, ok := GetUser(username)
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

	var username string
	sqliteDB.QueryRow("SELECT user_id FROM users WHERE token = ?", token).Scan(&username)
	if username == "" {
		return false
	}
	u, _ := GetUser(username)
	return u.Token == token
}
