package utils

import (
	"encoding/csv"
	"fmt"
	"log"
	"os"
)

func WriteMapsToCSV(maps []map[string]string, filename string) {
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
		"Protocol",
		"MyDevice_ip",
		"MyDevice_port",
		"Client_ip",
		"Client_port",
		"StartTime",
		"LastTime",
		"Fin",
		"InitWinBytesBwd",
		"InitWinBytesFwd",
		"BwdTotPacketLength",
		"BwdTotPackets",
		"BwdPacketLengthMin",
		"BwdPacketLengthStd",
		"BwdPacketLengthMean",
		"BwdPacketRate",
		"FwdHeaderLength",
		"FwdTotPackets",
		"PacketLengthStd",
		"AveragePacketSize",
		"FlowIATMin",
		"FlowIATMax",
		"FlowIATTotal",
		"FlowDuration",
	}
	if new != nil { //If file does not exist
		writer.Write(header)
	}

	//Rest of the datas
	for _, m := range maps {
		var record []string
		for _, key := range header {
			record = append(record, m[key])
		}
		if err := writer.Write(record); err != nil {
			log.Fatalf("Failed to write rows to file: %s", err)
		}
	}

}

func AccessBWLCsv() { //returns a mapping of key => BL or WL

}

func WriteBWL_toCSV() {

}
