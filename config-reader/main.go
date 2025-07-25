package main

import (
	"encoding/json"
	"fmt"
	"os"
)

type Config struct {
	NetworkZone string `json:"network_zone"`
}

var config Config

func loadConfig(filename string) error {
	// check if the file exists
	if _, err := os.Stat(filename); os.IsNotExist(err) {
		return fmt.Errorf("config file does not exist: %s", filename)
	}
	// read the file and parse the JSON
	data, err := os.ReadFile(filename)
	if err != nil {
		return fmt.Errorf("error reading config file: %v", err)
	}
	// parse the JSON data
	if err := json.Unmarshal(data, &config); err != nil {
		return fmt.Errorf("error parsing config file: %v", err)
	}
	fmt.Printf("Loaded config: %+v\n", config)
	return nil
}

func main() {
	fmt.Println("This is the config-reader main package.")
	configFile := "config.json"
	if err := loadConfig(configFile); err != nil {
		fmt.Printf("Failed to load config: %v\n", err)
		config = Config{
			NetworkZone: "default",
		}
	}
	fmt.Printf("Network Zone: %s\n", config.NetworkZone)
}
