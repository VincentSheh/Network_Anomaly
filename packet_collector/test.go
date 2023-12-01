// package main

// import (
// 	"fmt"
// 	"strconv"
// )

// func main() {
// 	fullFeatures := map[string]string{
// 		"Protocol":      "TCP", // Example values
// 		"MyDevice_ip":   "192.168.1.1",
// 		"MyDevice_port": "8080",
// 		// ... other key-value pairs ...
// 		"FlowDuration": strconv.FormatInt(123456, 10),
// 		// ... more key-value pairs ...
// 	}

// 	// Extracting keys to a slice
// 	var keys []string
// 	for key := range fullFeatures {
// 		keys = append(keys, key)
// 	}

// 	for _, key := range keys {
// 		fmt.Println(key)
// 	}
// }
