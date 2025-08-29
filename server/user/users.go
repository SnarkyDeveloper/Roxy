package user

import "golang.org/x/crypto/bcrypt"

type User struct {
	Username string `json:"username"`
	Password string `json:"password"` // hash. Secure for in mem use
	UserID   string `json:"user_id"`
	Token    string `json:"token"` // for API use and Auth checking
}

func HashPass(pass string) string {
	bcrypted, err := bcrypt.GenerateFromPassword([]byte(pass), 11)
	if err != nil {
		logger.Print("Failed to hash password:" + err.Error()) // non-fatal
		return ""
	}
	return string(bcrypted)
}

func CheckPass(pass, hash string) bool {
	return bcrypt.CompareHashAndPassword([]byte(hash), []byte(pass)) == nil
}

func hashUser(user User) User {
	user.Password = HashPass(user.Password)
	return user
}
