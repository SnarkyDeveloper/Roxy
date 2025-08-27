package config

import (
	"os"

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
