package exceptions

import "errors"

var (
	ErrInvalidCredentials = errors.New("Invalid credentials")
	ErrUserExists         = errors.New("User already exists")
	ErrConfigNotExists    = errors.New("Config directory does not exist. Are you using a custom OS?")
	ErrNotAuthenticated   = errors.New("You are not authenticated. Please login first.")
	ErrNoPermissions      = errors.New("Roxy client does not have permission to read and/or write to the config file.")
	ErrEmptyConfig        = errors.New("Non fatal, check error for first run. If you see this message ever please open an issue.") // check file in main, if not exists trigger signup/login
)
