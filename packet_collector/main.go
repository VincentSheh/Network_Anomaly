package main

import (
	"flag"
	"fmt"
	"log"

	// "net"
	"packet_collector/features"
	"packet_collector/utils"

	// "runtime"

	// "strings"
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
	tcpsrc, tcpdst = transportLayer.TransportFlow().Endpoints()
	fmt.Printf("IP Source: %s, IP Destination: %s, TCP Source: %s, TCP Destination: %s, Direction: %v, NetFlow: %s\n",
		ipsrc, ipdst, tcpsrc, tcpdst, direction, netFlow)

	return ipsrc, ipdst, tcpsrc, tcpdst, direction, netFlow
}

func processPackets(packetSource *gopacket.PacketSource, local_ip string) (int, int64) {

	recFlows := make(map[gopacket.Flow]*features.Flow)
	// Initialize BWList (Seperate from recFlows because key is source address)
	BWList := make(map[string]utils.BWInfo)
	//Start
	iterCount := 0
	var iterDuration int64 = 0
	for p := range packetSource.Packets() {

		iterCount++
		var currTime int64 = time.Now().UnixMilli()

		ipsrc, ipdst, tcpsrc, tcpdst, direction, netFlow := getPacketInfo(local_ip, &p)
		packet := new(features.Packet)      // Create a pointer to a new Packet instance
		packet.Init(p, direction, currTime) // Call Init on the pointer
		// print("PACKET INFO-----\n ")
		// packet.PrintPacketInfo()

		//Flow Creation or Add Packet to flow
		var flow *features.Flow
		if f, ok := recFlows[netFlow]; ok {
			flow = f
			recFlows[netFlow].AddPacket(*packet)
		} else {
			flow = new(features.Flow)
			flow.Init(
				packet,
				direction,
				ipsrc.String(),
				tcpsrc.String(),
				ipdst.String(),
				tcpdst.String(),
				currTime,
			)
			recFlows[netFlow] = flow
		}

		// TODO6: Recheck WL / BL => Remove the WL from the BWList, Forward the BL to NFQueue?
		key := flow.ClientIP + ":" + flow.ClientPort
		var isWL bool
		if info, isExist := BWList[key]; isExist {
			isWL = info.Bw == "white"
			if isWL && time.Now().Sub(info.LastCheck) > Config.WLRecheckInterval { //Pass to model
				info.Bw = "recheck"
				BWList[key] = info
			}
		}

		// TODO1: Is Time ellapse (of BL/WL/unassigned) > threshold __DONE__
		lastCheckDuration := flow.GetLastCheckDuration()

		if lastCheckDuration > Config.CheckInterval.Milliseconds() {
			// if lastCheckDuration > 0 {
			fmt.Printf("TCP: %s:%s -> %s:%s\n",
				ipsrc, tcpsrc, ipdst, tcpdst)
			fmt.Printf("FlowDuration: %d \n", lastCheckDuration)

			// TODO5: Check BWL: if WL skip inference __DONE__

			// TODO2: Send to Detection Model
			// isMaliciousProb = PostDetection()
			var isMalicious bool
			if isWL {
				isMalicious = false
			} else {
				isMalicious = flow.SendFlowData()
				// isMalicious = Config.Seed.Intn(10) == 0

			}

			// TODO3-1: Add to BWL __DONE__
			// TODO4: Process BWL => BL exec command line: iptables, __DONE__
			if isMalicious {
				BWList[key] = utils.BWInfo{
					Bw:        "black", //true means black list
					LastCheck: time.Now(),
				}

				// UNCOMMENT utils.BlackListIP(flow.Client_ip, flow.Client_port)
			} else { //Check if the duration is enough to be in WL
				flowDuration := flow.GetFlowDuration()
				if flowDuration > Config.WLDurationThreshold.Milliseconds() {
					BWList[key] = utils.BWInfo{
						Bw:        "white", //true means black list
						LastCheck: time.Now(),
					}
				}
			}

		}
		endIterTime := time.Now().UnixMilli() - currTime
		iterDuration += endIterTime

	}
	var featuresList []map[string]interface{}
	for _, flow := range recFlows {
		featuresList = append(featuresList, flow.GetFullFeatures())
	}
	// volumePath := "/pv/pv1/"
	volumePath := "./"
	utils.WriteMapsToCSV(featuresList, volumePath+"output.csv")
	// TODO3-2: Save to CSV
	utils.WriteBWL_toCSV(BWList)
	return iterCount, iterDuration
}

func main() {
	//Get Command Line Arguments
	path := flag.String("path", "./tcpdump/mycapture.pcap", "Path to Pcap File")
	flag.Parse()
	print(path, "\n")

	//Get Local IP
	// addrs_arr, _ := net.InterfaceAddrs()
	// var local_ip string
	// for _, addrs := range addrs_arr {
	// 	if ipnet, ok := addrs.(*net.IPNet); ok && !ipnet.IP.IsLoopback() {
	// 		ipAddr := ipnet.IP.String()
	// 		if strings.HasPrefix(ipAddr, "192.") {
	// 			local_ip = ipAddr
	// 			break
	// 		}
	// 	}
	// }
	local_ip := "172.16.189.72"
	fmt.Printf("Running Packet Filtering in %s \n", local_ip)

	// Use Pcap to capture packets
	// handle, err := pcap.OpenLive(*netInterface, 1600, true, pcap.BlockForever) //ifconfig to see active network interface
	handle, err := pcap.OpenOffline(*path)
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

	iterCount, iterDuration := processPackets(packetSource, local_ip)

	//Profiling
	fmt.Printf("Total Number of Packets %d \n", iterCount)
	fmt.Printf("Duration of all iterations %d \n", iterDuration)
}
