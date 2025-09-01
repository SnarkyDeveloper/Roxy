package config

import (
	"os"
	"strings"

	"gopkg.in/yaml.v3"
)

type Config struct {
	Host     string `yaml:"host"`
	Port     int    `yaml:"port"`
	LogLevel string `yaml:"log_level"`
	LogFile  string `yaml:"log_file"`
	Database struct {
		TTL    int    `yaml:"ttl"` // sec
		DBFile string `yaml:"path"`
	}
	Path string `yaml:"path"`
}

type Repo struct {
	Name string `json:"name"`
	ID   string `json:"id"`
}

func ParseConfig(filepath string) (*Config, error) {
	yamlFile, err := os.ReadFile(filepath)
	if err != nil {
		return nil, err
	}
	var config Config
	err = yaml.Unmarshal(yamlFile, &config)
	if err != nil {
		return nil, err
	}
	return &config, nil
}

// config must be mutable (this isn't rust but still :3)
func (config *Config) ParsePath() string {
	if config.Path == "" {
		panic("Path must be set in config")
	} else if strings.Contains(config.Path, "{") { // ie: /{username}/{repo} -> /:username/:repo (for httprouter)
		config.Path = strings.ReplaceAll(config.Path, "{", ":")
		config.Path = strings.ReplaceAll(config.Path, "}", "")
	}
	return config.Path
}
