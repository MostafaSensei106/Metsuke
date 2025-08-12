package config

import (
	"fmt"
	"os"
	"path/filepath"

	"gopkg.in/yaml.v3"
)

type VirusTotal struct {
	APIKey string `yaml:"VIRUSTOTAL_API_KEY"`
}

type NVD struct {
	APIKey string `yaml:"NVD_API_KEY"`
}

type Cache struct {
	Enabled   bool   `yaml:"enabled"`
	TTL       int    `yaml:"ttl"` // hours
	Directory string `yaml:"directory"`
}

type Output struct {
	Format   string `yaml:"format"` // json, text, table
	Colors   bool   `yaml:"colors"`
	SaveLogs bool   `yaml:"save_logs"`
	LogsPath string `yaml:"logs_path"`
}

type Parallel struct {
	MaxWorkers int `yaml:"max_workers"`
}

type Config struct {
	VirusTotal VirusTotal `yaml:"virustotal"`
	NVD        NVD        `yaml:"nvd"`
	Cache      Cache      `yaml:"cache"`
	Output     Output     `yaml:"output"`
	Parallel   Parallel   `yaml:"parallel"`
}

var GlobalConfig *Config

func getConfigDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: Unable to determine home directory: %v\n", err)
		os.Exit(1)
	}
	return filepath.Join(home, ".metsuke", "config")
}

func SaveConfigToKeyring() error {
	return nil
}

func InitConfig() error {
	GlobalConfig = &Config{}

	// Set defaults
	GlobalConfig.Cache.Enabled = true
	GlobalConfig.Cache.TTL = 24
	GlobalConfig.Cache.Directory = filepath.Join(os.TempDir(), "secscan-cache")
	GlobalConfig.Output.Format = "table"
	GlobalConfig.Output.Colors = true
	GlobalConfig.Output.SaveLogs = true
	GlobalConfig.Output.LogsPath = filepath.Join(os.TempDir(), "secscan-logs")
	GlobalConfig.Parallel.MaxWorkers = 10

	// Try to load config file
	configPath := filepath.Join(getConfigDir(), "config.yml")
	if _, err := os.Stat(configPath); err == nil {
		data, err := os.ReadFile(configPath)
		if err != nil {
			return err
		}

		err = yaml.Unmarshal(data, GlobalConfig)
		if err != nil {
			return err
		}
	}

	return nil
}
