package main

import (
    "fmt"
    "log"

    "github.com/google/gopacket"
    "github.com/google/gopacket/layers"
    "github.com/google/gopacket/pcap"
)

func main() {
    pcapFile := "mycapture.pcap"

    handle, err := pcap.OpenOffline(pcapFile)
    if err != nil {
        log.Fatal(err)
    }
    defer handle.Close()

    packetSource := gopacket.NewPacketSource(handle, handle.LinkType())
    for packet := range packetSource.Packets() {
        printPacketInfo(packet)
    }
}

func printPacketInfo(packet gopacket.Packet) {
    // Handle Ethernet layer
		fmt.Printf("I RUN \n")
    ethernetLayer := packet.Layer(layers.LayerTypeEthernet)
    if ethernetLayer != nil {
        ethernetPacket, _ := ethernetLayer.(*layers.Ethernet)
        fmt.Printf("Source MAC: %s, Destination MAC: %s\n", ethernetPacket.SrcMAC, ethernetPacket.DstMAC)
    }

    // Handle IPv4 layer
    ipv4Layer := packet.Layer(layers.LayerTypeIPv4)
    if ipv4Layer != nil {
        ipv4Packet, _ := ipv4Layer.(*layers.IPv4)
        fmt.Printf("IPv4 - Source IP: %s, Destination IP: %s\n", ipv4Packet.SrcIP, ipv4Packet.DstIP)
    }

    // Handle IPv6 layer
    ipv6Layer := packet.Layer(layers.LayerTypeIPv6)
    if ipv6Layer != nil {
        ipv6Packet, _ := ipv6Layer.(*layers.IPv6)
        fmt.Printf("IPv6 - Source IP: %s, Destination IP: %s\n", ipv6Packet.SrcIP, ipv6Packet.DstIP)
    }
}
