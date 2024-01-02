package main

import (
	"fmt"
	"log"
	"net"
	"packet_collector/features"
	"packet_collector/utils"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	// "github.com/subgraph/go-nfnetlink/nfqueue"
)

type BWInfo struct {
	bw         string // black or white list
	last_check time.Time
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

	var filter string = "tcp" //Add more e.g "tcp and port 80"
	err = handle.SetBPFFilter(filter)
	if err != nil {
		log.Fatal(err)
	}

	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())

	recFlows := make(map[gopacket.Flow]*features.Flow)
	i := 0
	// Initialize BWList (Seperate from recFlows because key is source address)
	BWList := make(map[string]BWInfo)
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
		var flow *features.Flow
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

		// TODO6: Recheck WL / BL => Remove the WL from the BWList, Forward the BL to NFQueue?
		key := flow.Client_ip + ":" + flow.Client_port
		var isWL bool
		if info, isExist := BWList[key]; isExist {
			isWL = true
			if time.Now().Sub(info.last_check) > Config.WLRecheckInterval {

			}
		}

		// TODO1: Is Time ellapse (of BL/WL/unassigned) > threshold __DONE__
		flowDuration := flow.GetFlowDuration()
		if (flowDuration - recFlows[netFlow].LastTime) > Config.CheckInterval.Milliseconds() {
			// TODO5: Check BWL: if WL skip inference __DONE__

			// TODO2: Send to Detection Model
			var isMalicious bool
			// isMaliciousProb = PostDetection()
			isMalicious = !isWL || Config.Seed.Intn(10) == 0 //If not in whitelist then perform inference

			// TODO3-1: Add to BWL __DONE__
			// TODO4: Process BWL => BL exec command line: iptables, __DONE__
			if isMalicious {
				BWList[key] = BWInfo{
					bw:         "black", //true means black list
					last_check: time.Now(),
				}
				utils.BlackListIP(flow.Client_ip, flow.Client_port)
			} else { //Check if the duration is enough to be in WL
				if flowDuration > Config.WLDurationThreshold.Milliseconds() {
					BWList[key] = BWInfo{
						bw:         "white", //true means black list
						last_check: time.Now(),
					}
				}
			}

			// TODO3-2: Save to CSV

		}

		i += 1
		if i == 200 {
			var featuresList []map[string]string
			for _, flow := range recFlows {
				featuresList = append(featuresList, flow.GetFullFeatures())
			}
			utils.WriteMapsToCSV(featuresList, "output.csv")
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
