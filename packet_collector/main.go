package main

import (
	"encoding/csv"
	"fmt"
	"log"
	"net"
	"os"

	"packet_collector/features"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	// "github.com/subgraph/go-nfnetlink/nfqueue"
)

func writeMapsToCSV(maps []map[string]string, filename string) {
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
func main() {
	//Get Local IP
	addrs_arr, _ := net.InterfaceAddrs()
	var local_ip string
	for _, addrs := range addrs_arr {
		if ipnet, ok := addrs.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
			ipAddr := ipnet.IP.String()
			if strings.HasPrefix(ipAddr, "192.") {
				local_ip = ipAddr
				break
			}
		}
	}
	fmt.Printf("Running Packet Filtering in %s \n", local_ip)

	// Use Pcap to capture packets
	handle, err := pcap.OpenLive("en0", 1600, true, pcap.BlockForever) //ifconfig to see active network interface
	if err != nil {
		log.Fatal((err))
	}
	defer handle.Close()

	var filter string = "tcp" //Add more e.g tcp and port 80
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	recFlows := make(map[gopacket.Flow]*features.Flow)
	i := 0

	//Start

	for p := range packetSource.Packets() {
		var t int64 = time.Now().UnixMilli()
		// Get packet length
		size := len(p.Data())
		//Network Layer decoding
		networkLayer := p.NetworkLayer()
		netFlow := networkLayer.NetworkFlow()
		ipsrc, ipdst := netFlow.Endpoints()
		// Get Direction
		var direction bool //In = 0, Out = 1
		if ipdst.String() == local_ip {
			direction = true
		} else {
			direction = false
		}
		fmt.Printf("Size of the packet is %d %v\n", size, direction)

		//Transport Layer decoding
		transportLayer := p.TransportLayer()
		tcpsrc, tcpdst := transportLayer.TransportFlow().Endpoints()
		fmt.Printf("TCP: %s:%s -> %s:%s\n",
			ipsrc, tcpsrc, ipdst, tcpdst)

		packet := new(features.Packet) // Create a pointer to a new Packet instance
		packet.Init(p, direction, t)   // Call Init on the pointer
		print("PACKET INFO-----\n ")
		packet.PrintPacketInfo()

		//Flow Creation or Add Packet to flow
		if _, ok := recFlows[netFlow]; ok {
			recFlows[netFlow].AddPacket(*packet)
		} else {
			flow := new(features.Flow)
			flow.Init(
				packet,
				direction,
				ipsrc.String(),
				tcpsrc.String(),
				ipdst.String(),
				tcpdst.String(),
				t,
			)
			recFlows[netFlow] = flow
		}

		i += 1
		if i == 200 {
			var featuresList []map[string]string
			for _, flow := range recFlows {
				featuresList = append(featuresList, flow.GetFullFeatures())
			}
			writeMapsToCSV(featuresList, "output.csv")
			break
		}
	}

}

// q := nfqueue.NewNFQueue(1)
// ps, err := q.Open()
// if err != nil {
// 	fmt.Printf("Error opening NFQueue: %v\n", err)
// 	os.Exit(1)
// }
// defer q.Close()

// recFlows := make(map[gopacket.Flow]*features.Flow)
// i := 0

// for p := range ps {
// 	var t int64 = time.Now().UnixMilli()
// 	// Get packet length
// 	size := len(p.Packet.Data())
// 	//Network Layer decoding
// 	networkLayer := p.Packet.NetworkLayer()
// 		netFlow := networkLayer.NetworkFlow()
// 		ipsrc, ipdst := netFlow.Endpoints()
// 		// Get Direction
// 		var direction bool //In = 0, Out = 1
// 		if ipdst.String() == local_ip {
// 			direction = true
// 		} else {
// 			direction = false
// 		}
// 		fmt.Printf("Size of the packet is %d %v\n", size, direction)

// 		//Transport Layer decoding
// 		transportLayer := p.Packet.TransportLayer()
// 		tcpsrc, tcpdst := transportLayer.TransportFlow().Endpoints()
// 		fmt.Printf("TCP: %s:%s -> %s:%s\n",
// 			ipsrc, tcpsrc, ipdst, tcpdst)

// 		packet := new(features.Packet)   // Create a pointer to a new Packet instance
// 		packet.Init(p.Packet, direction) // Call Init on the pointer
// 		print("PACKET INFO-----\n ")
// 		packet.PrintPacketInfo()

// 		//Flow Creation or Add Packet to flow
// 		if _, ok := recFlows[netFlow]; ok {
// 			recFlows[netFlow].AddPacket(*packet)
// 		} else {
// 			flow := new(features.Flow)
// 			flow.Init(
// 				packet,
// 				direction,
// 				ipsrc.String(),
// 				tcpsrc.String(),
// 				ipdst.String(),
// 				tcpdst.String(),
// 				t,
// 			)
// 			recFlows[netFlow] = flow
// 		}

// 		p.Accept()

// 		i += 1
// 		if i == 10 {
// 			var featuresList []map[string]string
// 			for _, flow := range recFlows {
// 				featuresList = append(featuresList, flow.GetFullFeatures())
// 			}
// 			writeMapsToCSV(featuresList, "output.csv")
// 			break
// 		}
// 	}

// }
