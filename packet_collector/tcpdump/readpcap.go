package main

import (
	"fmt" // Import the fmt package to print messages to the console.
	"log" // Import the log package to log errors to the console.

	"github.com/google/gopacket"        // Import the gopacket package to decode packets.
	"github.com/google/gopacket/layers" // Import the layers package to access the various network layers.
	"github.com/google/gopacket/pcap"   // Import the pcap package to capture packets.
)

func main() {

	// Open up the pcap file for reading
<<<<<<< HEAD
	handle, err := pcap.OpenOffline("mycapture.pcap")
=======
	handle, err := pcap.OpenOffline("mycapture1.pcap")
>>>>>>> 30a1599564b3e102a4a339cd8b4e9ec44dfb3e82
	if err != nil {
		log.Fatal(err)
	}
	defer handle.Close()

	// Loop through packets in file
	packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
	for packet := range packetSource.Packets() {

		// Print the packet details
		fmt.Println(packet.String())

		// Extract and print the Ethernet layer
		ethLayer := packet.Layer(layers.LayerTypeEthernet)
		if ethLayer != nil {
			ethPacket, _ := ethLayer.(*layers.Ethernet)
			fmt.Println("Ethernet source MAC address:", ethPacket.SrcMAC)
			fmt.Println("Ethernet destination MAC address:", ethPacket.DstMAC)
		}

		// Extract and print the IP layer
		ipLayer := packet.Layer(layers.LayerTypeIPv4)
		if ipLayer != nil {
			ipPacket, _ := ipLayer.(*layers.IPv4)
			fmt.Println("IP source address:", ipPacket.SrcIP)
			fmt.Println("IP destination address:", ipPacket.DstIP)
		}
	}
}
