package features

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

type Packet struct {
	Packet       gopacket.Packet
	Time         int64
	Direction    bool //0 is in, 1 is out
	Protocol     string
	HeaderLength uint8
	Length       int
	TCPWindow    uint16
	TCPFlags     []string //FIN, SYN, RST, PSH, ACK, URG, ECE, CWR, NS
	ClientIp     string
}

func (p *Packet) Init(packet gopacket.Packet, direction bool) {
	p.Packet = packet
	p.Time = time.Now().UnixMicro()
	p.Direction = direction
	p.HeaderLength, p.Protocol = p.GetIPData()
	p.Length = p.GetPacketLength()
	p.TCPWindow, p.TCPFlags = p.GetTCPData()
}

func (p Packet) GetPacketLength() int {
	return len(p.Packet.Data())
}

func (p Packet) GetIPData() (uint8, string) {
	var HeaderLength uint8
	var Protocol string
	//IP Segment
	ipLayer := p.Packet.Layer(layers.LayerTypeIPv4)
	if ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		HeaderLength = ip.IHL * 4
		Protocol = ip.Protocol.String()
		// p. Add more IP layer variables
	} else {
		HeaderLength = 8
	}
	return HeaderLength, Protocol

}

func (p Packet) GetTCPData() (uint16, []string) {
	var TCPWindow uint16
	var TCPFlags []string
	//TCP Segment
	tcpLayer := p.Packet.Layer(layers.LayerTypeTCP)
	if tcpLayer != nil {
		tcp, _ := tcpLayer.(*layers.TCP)
		TCPWindow = tcp.Window

		if tcp.FIN {
			TCPFlags = append(TCPFlags, "FIN")
		}
		if tcp.SYN {
			TCPFlags = append(TCPFlags, "SYN")
		}
		if tcp.RST {
			TCPFlags = append(TCPFlags, "RST")
		}
		if tcp.PSH {
			TCPFlags = append(TCPFlags, "PSH")
		}
		if tcp.ACK {
			TCPFlags = append(TCPFlags, "ACK")
		}
		if tcp.URG {
			TCPFlags = append(TCPFlags, "URG")
		}
		if tcp.ECE {
			TCPFlags = append(TCPFlags, "ECE")
		}
		if tcp.CWR {
			TCPFlags = append(TCPFlags, "CWR")
		}
		if tcp.NS {
			TCPFlags = append(TCPFlags, "NS")
		}
	}
	return TCPWindow, TCPFlags
}
func (p Packet) PrintPacketInfo() {
	fmt.Printf("Received at: %d, Protocol %s, Direction: %v, Header Length: %d bytes, Packet Length: %d, TCP Window: %d \n", p.Time, p.Protocol, p.Direction, p.HeaderLength, p.Length, p.TCPWindow)
}
