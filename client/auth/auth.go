package auth

import (
	"encoding/json"
	"net/http"
	"os"
	"roxy/client/exceptions"
	"time"
)

type Config struct {
	Token     string `json:"token"`
	PublicURL string `json:"public_url"` // reverse proxie's public URL (ie: roxy.example.com)
	Port      string `json:"port"`       // port on which the reverse proxy listens (ie: 8080). 0 for no port
}

type AuthResponse struct {
	Message string `json:"message"`
	Token   string `json:"token"`
}

type AuthStatus struct {
	Status        string `json:"status"`
	Authenticated bool   `json:"authenticated"`
}

func GetConfig() (Config, error) {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return Config{}, exceptions.ErrConfigNotExists
	}

	cfg = cfg + "/roxy"
	os.MkdirAll(cfg, 0755) // 0755 = rwxr-xr-x
	_, err = os.Stat(cfg + "/config.json")
	if os.IsNotExist(err) {
		os.Create(cfg + "/config.json")
	}
	f, err := os.OpenFile(cfg+"/config.json", os.O_RDONLY, 0) // read only
	if err != nil {
		return Config{}, exceptions.ErrNoPermissions
	}
	defer f.Close()
	var config Config
	err = json.NewDecoder(f).Decode(&config)
	if err != nil {
		return config, exceptions.ErrEmptyConfig // non fatal, check error for first run
	}
	return config, nil
}

func SaveConfig(config Config) error {
	cfg, err := os.UserConfigDir()
	if err != nil {
		return exceptions.ErrConfigNotExists
	}

	cfg = cfg + "/roxy"
	os.MkdirAll(cfg, 0755)                                                  // 0755 = rwxr-xr-x
	f, err := os.OpenFile(cfg+"/config.json", os.O_WRONLY|os.O_TRUNC, 0644) // write only, truncate
	if err != nil {
		return exceptions.ErrNoPermissions
	}
	defer f.Close()
	err = json.NewEncoder(f).Encode(config)
	if err != nil {
		return err
	}
	return nil
}

func Register(username, password string) (string, error) {
	cfg, err := GetConfig()
	if err != nil {
		return "", err
	}
	cfg.PublicURL = "http://" + cfg.PublicURL
	var url string
	if cfg.Port != "0" {
		url = cfg.PublicURL + ":" + cfg.Port
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest(http.MethodPost, url+"/signup", nil)
	if err != nil {
		return "", err
	}
	req.PostForm.Set("username", username)
	req.PostForm.Set("password", password)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", exceptions.ErrInvalidCredentials
	}

	var result AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&result)

	if err != nil {
		return "", err
	}

	return result.Token, nil
}

func Login(username, password string) (string, error) {
	cfg, err := GetConfig()
	if err != nil {
		return "", err
	}
	cfg.PublicURL = "http://" + cfg.PublicURL
	var url string
	if cfg.Port != "0" {
		url = cfg.PublicURL + ":" + cfg.Port
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest(http.MethodPost, url+"/login", nil)
	if err != nil {
		return "", err
	}
	req.PostForm.Set("username", username)
	req.PostForm.Set("password", password)
	resp, err := client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return "", exceptions.ErrInvalidCredentials
	}

	var result AuthResponse
	err = json.NewDecoder(resp.Body).Decode(&result)

	if err != nil {
		return "", err
	}

	return result.Token, nil
}

func ValidateToken() (bool, error) {
	cfg, err := GetConfig()
	if err != nil {
		return false, err
	}
	if cfg.Token == "" {
		return false, exceptions.ErrNotAuthenticated
	}
	cfg.PublicURL = "http://" + cfg.PublicURL
	var url string
	if cfg.Port != "0" {
		url = cfg.PublicURL + ":" + cfg.Port
	}
	client := &http.Client{
		Timeout: 10 * time.Second,
	}
	req, err := http.NewRequest(http.MethodPost, url+"/status", nil)
	if err != nil {
		return false, err
	}
	req.Header.Set("Authorization", cfg.Token)
	resp, err := client.Do(req)
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusCreated {
		return false, exceptions.ErrInvalidCredentials
	}

	var result AuthStatus
	err = json.NewDecoder(resp.Body).Decode(&result)

	if err != nil {
		return false, err
	}

	return result.Authenticated, nil
}
