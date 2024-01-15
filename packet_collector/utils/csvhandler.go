package utils

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
	"time"
)

func WriteMapsToCSV(maps []map[string]interface{}, filename string) {
	var file *os.File
	var new error
	if _, new = os.Stat(filename); new == nil {
		fmt.Printf("File %s already exists. Not creating a new file.\n", filename)
		file, _ = os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)

	} else {
		fmt.Printf("File %s does not exist. Creating a new file.\n", filename)
		file, _ = os.Create(filename)
	}

	defer file.Close()
	writer := csv.NewWriter((file))
	defer writer.Flush()

	//Extract the header,
	//the behavior of Go maps prevent users from having a predefined order of keys
	// var header []string
	// for key := range maps[0] {
	// 	header = append(header, key)
	// }
	header := []string{
		"Init_Win_bytes_forward",
		"Bwd Packets/s",
		"Init_Win_bytes_backward",
		"Flow Duration",
		"Packet Length Std",
		"Destination Port",
		"Average Packet Size",
		"Total Length of Bwd Packets",
		"Bwd Packet Length Min",
		"Fwd Header Length",
		"Total Backward Packets",
		"Total Length of Fwd Packets",
		"Bwd Packet Length Mean",
		"Flow IAT Min",
	}
	if new != nil { //If file does not exist
		writer.Write(header)
	}

	//Rest of the datas
	for _, m := range maps {
		var record []string
		for _, key := range header {
			record = append(record, fmt.Sprintf("%v", m[key]))
		}
		if err := writer.Write(record); err != nil {
			log.Fatalf("Failed to write rows to file: %s", err)
		}
	}

}

func AccessBWLCsv() { //returns a mapping of key => BL or WL

}

func WriteBWL_toCSV(m map[string]BWInfo) {
	header := []string{
		"Address",
		"Status",
		"Time",
	}
	var file *os.File
	var new error
	volumePath := "/pv/pv1/"
	filename := volumePath + "bwlist.csv"
	if _, new = os.Stat(filename); new == nil {
		fmt.Printf("File %s already exists. Not creating a new file.\n", filename)
		file, _ = os.OpenFile(filename, os.O_WRONLY|os.O_CREATE|os.O_APPEND, 0644)

	} else {
		fmt.Printf("File %s does not exist. Creating a new file.\n", filename)
		file, _ = os.Create(filename)
	}

	defer file.Close()
	writer := csv.NewWriter((file))
	defer writer.Flush()

	if new != nil { //If file does not exist
		writer.Write(header)
	}
	// Iterate over the map and write data
	for key, info := range m {
		record := []string{key, info.Bw, info.LastCheck.Format(time.RFC3339)}
		if err := writer.Write(record); err != nil {
			panic(err)
		}
	}

}
