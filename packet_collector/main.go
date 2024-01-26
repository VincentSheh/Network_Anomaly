package main

import (
	"flag"
	"fmt"
	"log"
	"net"
	"packet_collector/features"
	"packet_collector/utils"
	"runtime"
	"strings"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/pcap"
	"github.com/shirou/gopsutil/cpu"
	// "github.com/subgraph/go-nfnetlink/nfqueue"
)

func measureCPU(cpuUsage chan float64, memUsage chan float64, end_exec *time.Ticker) {
	var totalCPU float64
	var totalMem uint64
	var count float64
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()

	for {
		select {
		case <-end_exec.C:
			cpuUsage <- totalCPU / count
			memUsage <- float64(totalMem) / count
			return
		case <-ticker.C:
			//CPU
			percent, err := cpu.Percent(time.Second, false)
			if err != nil {
				fmt.Printf("Error measuring CPU: %v\n", err)
				continue
			}
			if len(percent) > 0 {
				totalCPU += percent[0]
				count++
			}
			//Memory
			var m runtime.MemStats
			runtime.ReadMemStats(&m)
			totalMem += m.TotalAlloc
		}
	}
}
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
	networkLayer := packet.NetworkLayer()
	netFlow := networkLayer.NetworkFlow()
	ipsrc, ipdst := netFlow.Endpoints()
	// Get Direction
	var direction bool //In = 0, Out = 1
	if ipdst.String() == local_ip {
		direction = true
	} else {
		direction = false
	}
	// size := len(p.Data())
	// fmt.Printf("Size of the packet is %d %v\n", size, direction)

	//Transport Layer decoding
	transportLayer := packet.TransportLayer()
	tcpsrc, tcpdst := transportLayer.TransportFlow().Endpoints()
	return ipsrc, ipdst, tcpsrc, tcpdst, direction, netFlow
}

func processPackets(packetSource *gopacket.PacketSource, local_ip string, run_ticker *time.Ticker) (int, int64) {

	recFlows := make(map[gopacket.Flow]*features.Flow)
	// Initialize BWList (Seperate from recFlows because key is source address)
	BWList := make(map[string]utils.BWInfo)
	//Start
	iterCount := 0
	var iterDuration int64 = 0
	for p := range packetSource.Packets() {
		select {
		case <-run_ticker.C:
			var featuresList []map[string]interface{}
			for _, flow := range recFlows {
				featuresList = append(featuresList, flow.GetFullFeatures())
			}
			volumePath := "/pv/pv1/"
			utils.WriteMapsToCSV(featuresList, volumePath+"output.csv")
			// TODO3-2: Save to CSV
			utils.WriteBWL_toCSV(BWList)
			return iterCount, iterDuration
		default:
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

	}
	return 0, 0

}

func main() {
	//Get Command Line Arguments
	path := flag.String("path", "./tcpdump/mycapture.pcap", "Path to Pcap File")
	flag.Parse()
	print(path, "\n")
	//Set timer

	//Profiling
	cpuUsage := make(chan float64)
	cpuBefore, _ := cpu.Percent(3*time.Second, false)

	// Memory
	memUsage := make(chan float64)
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	MemBefore := m.TotalAlloc
	run_ticker := time.NewTicker(20 * time.Second)
	go measureCPU(cpuUsage, memUsage, run_ticker) //CPU

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

	iterCount, iterDuration := processPackets(packetSource, local_ip, run_ticker)

	//Profiling
	cpuAverage := <-cpuUsage
	memAverage := <-memUsage
	fmt.Printf("Total Number of Packets %d \n", iterCount)
	fmt.Printf("Duration of all iterations %d \n", iterDuration)
	fmt.Printf("CPU Usage Before vs Average CPU usage: %f%% vs %f%%\n", cpuBefore[0], cpuAverage)
	fmt.Printf("Memory Usage Before vs Average Memory usage: %d vs %f\n", MemBefore, memAverage)
}
