package user

type User struct {
	Username string `json:"username"`
	Password string `json:"password"` // hash. Secure for in mem use
	UserID   string `json:"user_id"`
}
