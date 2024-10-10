// internal/dataloader/loadjson.go
package dataloader

import (
    "encoding/json"
    "fmt"
    "io/ioutil"
    "os"
    "strconv"
)

// PortService represents the structure for the port service in the JSON file
type PortService struct {
    Protocol string `json:"protocol"`
    Service string `json:"service"`
}

// LoadPortServiceMap loads the port and service information from the JSON file
func LoadPortServiceMap(filename string) (map[int]PortService, error) {
    // Open the JSON file
    file, err := os.Open(filename)
    if err != nil {
        return nil, fmt.Errorf("failed to open file: %v", err)
    }
    defer file.Close()

    // Read the contents of the file
    byteValue, err := ioutil.ReadAll(file)
    if err != nil {
        return nil, fmt.Errorf("failed to read file: %v", err)
    }

    // Temporary map to hold string keys before conversion
    var tempMap map[string]PortService
    err = json.Unmarshal(byteValue, &tempMap)
    if err != nil {
        return nil, fmt.Errorf("failed to unmarshal JSON: %v", err)
    }

    // Create final map with int keys
    portServiceMap := make(map[int]PortService)
    for key, value := range tempMap {
        port, err := strconv.Atoi(key) // convert string key to int
        if err != nil {
            return nil, fmt.Errorf("failed to convert port key to int: %v", err)
        }
        portServiceMap[port] = value
    }

    return portServiceMap, nil
}
