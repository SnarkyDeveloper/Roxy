package main

import (
	"roxy/client/auth"
	"roxy/client/exceptions"

	"github.com/manifoldco/promptui"
)

func setup() {
	// first run
	println("Welcome to Roxy! It looks like this is your first time running the client. Let's get you set up.")
	var cfg auth.Config
	prompt := promptui.Prompt{
		Label: "Enter the public URL of your Roxy server (e.g. roxy.example.com)",
		Validate: func(input string) error {
			if input == "" {
				return exceptions.ErrInvalidCredentials
			}
			return nil
		},
	}
	res, err := prompt.Run()
	if err != nil {
		println("Prompt failed:", err.Error())
		return
	}
	cfg.PublicURL = res

	prompt = promptui.Prompt{
		Label: "Enter the port your Roxy server is listening on (e.g. 8080). Enter 0 for no port.",
		Validate: func(input string) error {
			if input == "" {
				return exceptions.ErrInvalidCredentials
			}
			return nil
		},
	}
	res, err = prompt.Run()
	if err != nil {
		println("Prompt failed:", err.Error())
		return
	}

	cfg.Port = res
	err = auth.SaveConfig(cfg)
	if err != nil {
		println("Failed to save config:", err.Error())
		return
	}

	prompt = promptui.Prompt{
		Label: "Enter your Roxy username",
		Validate: func(input string) error {
			if input == "" {
				return exceptions.ErrInvalidCredentials
			}
			return nil
		},
	}
	res, err = prompt.Run()
	if err != nil {
		println("Prompt failed:", err.Error())
		return
	}
	username := res

	prompt = promptui.Prompt{
		Label: "Enter your Roxy password",
		Mask:  '*',
		Validate: func(input string) error {
			if input == "" {
				return exceptions.ErrInvalidCredentials
			}
			return nil
		},
	}
	res, err = prompt.Run()
	if err != nil {
		println("Prompt failed:", err.Error())
		return
	}
	password := res

	token, err := auth.Register(username, password)

	if err != nil {
		// try login instead
		token, err = auth.Login(username, password)
		if err != nil {
			println("Failed to register or login:", err.Error())
			return
		}
	}
	cfg.Token = token
	err = auth.SaveConfig(cfg)
	if err != nil {
		println("Failed to save config:", err.Error())
		return
	}

	println("You have successfully registered your account,", username, "at", cfg.PublicURL)
}

func main() {
	_, err := auth.GetConfig()
	if err == exceptions.ErrEmptyConfig {
		setup()
	}
	authenticated, err := auth.ValidateToken()
	if err == exceptions.ErrNotAuthenticated {
		setup()
	}
	if err != nil {
		println("Failed to validate token:", err.Error())
		return
	}
	if !authenticated {
		setup()
	}

}
