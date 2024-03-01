package main

import (
	"fmt"
	"log"
	"runtime"

	// "net"
	"packet_collector/features"
	"packet_collector/utils"

	// "runtime"

	// "strings"
	"flag"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	// "github.com/shirou/gopsutil/cpu"
	// "github.com/subgraph/go-nfnetlink/nfqueue"
)

func getPacketInfo(local_ip string, p *gopacket.Packet) (
	gopacket.Endpoint,
	gopacket.Endpoint,
	gopacket.Endpoint,
	gopacket.Endpoint,
	bool,
	gopacket.Flow,
) {
	//Network Layer decoding
	packet := *p
	var ipsrc, ipdst, tcpsrc, tcpdst gopacket.Endpoint
	var direction bool
	var netFlow gopacket.Flow
	networkLayer := packet.NetworkLayer()
	if networkLayer != nil {
		netFlow := networkLayer.NetworkFlow()
		ipsrc, ipdst = netFlow.Endpoints()
		// Get Direction
		if ipdst.String() == local_ip {
			direction = true
		} else {
			direction = false
		}
		// size := len(p.Data())
		// fmt.Printf("Size of the packet is %d %v\n", size, direction)
	}

	//Transport Layer decoding
	transportLayer := packet.TransportLayer()
	if transportLayer != nil {
		tcpsrc, tcpdst = transportLayer.TransportFlow().Endpoints()

	}
	// fmt.Printf("IP Source: %s, IP Destination: %s, TCP Source: %s, TCP Destination: %s, Direction: %v, NetFlow: %s\n",
	// 	ipsrc, ipdst, tcpsrc, tcpdst, direction, netFlow)
	return ipsrc, ipdst, tcpsrc, tcpdst, direction, netFlow
}

func processPackets(
	maxIterLimit int,
	packetSource *gopacket.PacketSource,
	recFlows *map[gopacket.Flow]*features.Flow,
	BWList *map[string]utils.BWInfo,
	local_ip string,
	filename string,

) (int, int64, int, map[int]int64) {

	//Start
	iterCount := 0
	detectCount := 0
	var iterDuration int64 = 0
	timeMap := make(map[int]int64)

	for p := range packetSource.Packets() {

		var currTime int64 = time.Now().UnixMilli()
		pktTimestamp := p.Metadata().Timestamp.UnixMilli()

		ipsrc, ipdst, tcpsrc, tcpdst, direction, netFlow := getPacketInfo(local_ip, &p)
		packet := new(features.Packet)      // Create a pointer to a new Packet instance
		packet.Init(p, direction, currTime) // Call Init on the pointer
		// print("PACKET INFO-----\n ")
		// packet.PrintPacketInfo()

		//Flow Creation or Add Packet to flow
		var flow *features.Flow
		if f, ok := (*recFlows)[netFlow]; ok {
			flow = f
			(*recFlows)[netFlow].AddPacket(*packet)
		} else {
			flow = new(features.Flow)
			flow.Init(
				packet,
				direction,
				ipsrc.String(),
				tcpsrc.String(),
				ipdst.String(),
				tcpdst.String(),
				pktTimestamp,
			)
			(*recFlows)[netFlow] = flow
		}

		// TODO6: Recheck WL / BL => Remove the WL from the BWList, Forward the BL to NFQueue?
		key := flow.ClientIP + ":" + flow.ClientPort
		var isWL bool
		if info, isExist := (*BWList)[key]; isExist {
			isWL = info.Bw == "white"
			if isWL && time.Since(info.LastCheck) > Config.WLRecheckInterval { //Pass to model
				info.Bw = "recheck"
				(*BWList)[key] = info
			}
		}

		// TODO1: Is Time ellapse (of BL/WL/unassigned) > threshold __DONE__
		lastCheckDuration := flow.GetLastCheckDuration()
		if lastCheckDuration > Config.CheckInterval.Milliseconds() {
			// if lastCheckDuration > 0 {
			// fmt.Printf("TCP: %s:%s -> %s:%s\n",
			// 	ipsrc, tcpsrc, ipdst, tcpdst)
			// fmt.Printf("FlowDuration: %d \n", lastCheckDuration)

			// TODO5: Check BWL: if WL skip inference __DONE__

			// TODO2: Send to Detection Model
			// isMaliciousProb = PostDetection()
			// var isMalicious bool
			if isWL {
				// isMalicious = false
			} else {
				// _ = flow.SendFlowData() //CHANGE THIS
				// detectCount++
				// isMalicious = flow.SendFlowData() //CHANGE THIS

				// isMalicious = Config.Seed.Intn(10) == 0
			}

			// TODO3-1: Add to BWL __DONE__
			// TODO4: Process BWL => BL exec command line: iptables, __DONE__
			// if isMalicious {
			// 	(*BWList)[key] = utils.BWInfo{
			// 		Bw:        "black", //true means black list
			// 		LastCheck: time.Now(),
			// 	}

			// 	// UNCOMMENT utils.BlackListIP(flow.Client_ip, flow.Client_port)
			// } else { //Check if the duration is enough to be in WL
			// 	flowDuration := flow.GetFlowDuration()
			// 	if flowDuration > Config.WLDurationThreshold.Milliseconds() {
			// 		(*BWList)[key] = utils.BWInfo{
			// 			Bw:        "white", //true means black list
			// 			LastCheck: time.Now(),
			// 		}
			// 	}
			// }
		}
		// Set Maximum Iteration
		iterCount++

		if iterCount >= maxIterLimit {
			if maxIterLimit == 0 {
				continue
			}
			break
		}

		endIterTime := time.Now().UnixMilli() - currTime
		iterDuration += endIterTime

		if iterCount%10000 == 0 {
			fmt.Printf("%d Iteration", iterCount)
			timeMap[iterCount] = iterDuration
		}

	}
	var featuresList []map[string]interface{}
	for _, flow := range *recFlows {
		featuresList = append(featuresList, flow.GetFullFeatures())
		flow.SendFlowData()
		detectCount++

	}
	// volumePath := "/pv/pv1/"
	volumePath := "./"
	utils.WriteMapsToCSV(featuresList, volumePath+filename)
	// TODO3-2: Save to CSV
	utils.WriteBWL_toCSV((*BWList))
	return iterCount, iterDuration, detectCount, timeMap
}

func main() {
	var filename string
	flag.StringVar(&filename, "filename", "output.csv", "CSV Filename")
	var maxIterLimit int
	flag.IntVar(&maxIterLimit, "iterations", 0, "Maximum Iterations")
	flag.Parse()

	local_ip := "192.168.50.30"
	fmt.Printf("Running Packet Filtering in %s \n", local_ip)

	// Use Pcap to capture packets
	// handle, err := pcap.OpenLive(*netInterface, 1600, true, pcap.BlockForever) //ifconfig to see active network interface

	// Read files
	// file_initial := "./capture_*"
	// files, err := filepath.Glob(file_initial)
	// for _, file := range files {
	// 	fmt.Println(file)
	// }

	totIterCount := 0
	totIterDuration := 0
	file := "merged.pcap"

	recFlows := make(map[gopacket.Flow]*features.Flow)
	BWList := make(map[string]utils.BWInfo) // Initialize BWList (Seperate from recFlows because key is source address)

	fmt.Printf("------- Reading %s ---------\n", file)
	iterMap := make(map[int]int)

	for i := 0; i < 5; i++ {

		startTime := time.Now()
		handle, err := pcap.OpenOffline(file)
		if err != nil {
			log.Printf("Error opening pcap file %s: %v\n", file, err)
		}
		// var filter string = "tcp" //Add more e.g "tcp and port 80"
		// err = handle.SetBPFFilter(filter)
		// if err != nil {
		// 	log.Fatal(err)
		// }
		packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
		defer handle.Close()
		iterCount, iterDuration, detectCount, timeMap := processPackets(maxIterLimit, packetSource, &recFlows, &BWList, local_ip, filename)
		totIterCount += iterCount
		totIterDuration += int(iterDuration)
		iterMap[totIterCount] = totIterDuration
		if err != nil {
			log.Fatal((err))
		}

		// Profiling
		endTime := time.Now()
		duration := endTime.Sub(startTime)

		fmt.Printf("%d Packets took %s to execute.\n", totIterCount, duration)

		fmt.Printf("Total Number of Packets %d \n", totIterCount)
		fmt.Printf("Duration of all iterations %d \n", totIterDuration)
		fmt.Printf("Detection count: %d \n", detectCount)
		for iter, totDuration := range timeMap {
			fmt.Printf("[%d, %d], \n", iter, totDuration)
		}
		runtime.GC()
	}

	for iter, totDuration := range iterMap {
		fmt.Printf("[%d, %d], \n", iter, totDuration)
	}

}
