package features

import (
	"math"
	"strconv"
	"time"
)

// Top Feature Names: ['Destination_Port', 'Init_Win_bytes_backward', 'Init_Win_bytes_forward', 'Fwd_IAT_Min', 'Fwd_Header_Length', 'Flow_IAT_Min', 'Flow_Duration', 'Bwd_IAT_Min', 'Flow_Bytes/s', 'Bwd_Packet_Length_Std', 'Total_Length_of_Fwd_Packets', 'Packet_Length_Std', 'PSH_Flag_Count', 'Bwd_Packet_Length_Min', 'Total_Fwd_Packets', 'min_seg_size_forward', 'Total_Backward_Packets', 'Bwd_Packets/s', 'Fwd_Packet_Length_Max', 'Fwd_IAT_Mean']
type Flow struct {
	//Features Obtained from packet information
	Protocol      string
	MyDevice_ip   string
	MyDevice_port string
	Client_ip     string
	Client_port   string
	// Direction is bidirectional!

	//We dont need to import because it is within the same package
	FwdPackets []Packet
	BwdPackets []Packet

	StartTime int64 //for flow duration
	LastTime  int64
	LastCheck int64
	Fin       bool

	InitWinBytesBwd int64 //1.39
	InitWinBytesFwd int64 //1.24

	//Calculated Features
	//Get BwdPacketStats()
	// BwdTotPacketLength  int64 //0.48
	// BwdTotPackets       int64
	// BwdPacketLengthMin  uint32  //1.14
	// BwdPacketLengthStd  float64 //2.04
	// BwdPacketLengthMean float64 //0.4
	// BwdPacketRate       int64   //0.39

	//Get ForwardPacketStats()
	// FwdHeaderLength int64 //0.4
	// TODO - FwdIATMin       int64 //0.38
	// FwdTotPackets int64 // 0.34
	// TODO - MinSegSizeForward int64 //0.53

	//Get PacketStats()
	// PacketLengthStd   int64   //0.71
	// AveragePacketSize float64 //0.32
	// TODO - IdleMin            int64 //0.51

	Flow_IAT_Arr []int64
	//GetIATStats()
	// Flow IAT Min   int64 //0.31
	// Flow IAT Max   int64 //0.26
	// Flow IAT Total int64 //0.26

	//GetFlowDuration
	// Flow Duration  int64 //0.22
}

func (f *Flow) Init(firstPacket *Packet,
	direction bool,
	ipsrc string,
	tcpsrc string,
	ipdst string,
	tcpdst string,
	t int64) {

	f.Protocol = firstPacket.Protocol
	if direction { //If traffic is inbound
		f.MyDevice_ip = ipdst
		f.MyDevice_port = tcpdst
		f.Client_ip = ipsrc
		f.Client_port = tcpsrc
	} else {
		f.MyDevice_ip = ipsrc
		f.MyDevice_port = tcpsrc
		f.Client_ip = ipdst
		f.Client_port = tcpdst
	}
	f.StartTime = t
	f.LastTime = t
	f.LastCheck = t

	f.AddPacket(*firstPacket)
}

func (f *Flow) AddPacket(packet Packet) {
	if f.StartTime != f.LastTime {
		f.Flow_IAT_Arr = append(f.Flow_IAT_Arr, packet.Time-f.LastTime)
	}

	f.LastTime = packet.Time
	if packet.Direction { //If traffic is inbound
		f.BwdPackets = append(f.BwdPackets, packet)
		if f.InitWinBytesBwd == 0 { //Recheck Definition
			f.InitWinBytesBwd = packet.TCPWindow
		}

		//OUTBOUND PACKETS
	} else {
		f.FwdPackets = append(f.FwdPackets, packet)
		if f.InitWinBytesFwd == 0 {
			f.InitWinBytesFwd = packet.TCPWindow
		}

	}
	f.Fin = f.GetFin(packet)

}

func (f Flow) GetBwdPacketStats() (int64, int64, int, float64, float64, float64) {
	if len(f.BwdPackets) == 0 {
		return 0, 0, 0, 0, 0, 0
	}
	BwdPacketLengthMin := f.BwdPackets[0].Length
	// max :=f.BwdPackets[0]
	var BwdTotPacketLength int64 = 0
	var BwdTotPackets int64 = 0
	var BwdPacketRate float64 = 0

	for _, pkt := range f.BwdPackets {
		BwdTotPacketLength += int64(pkt.Length)
		BwdTotPackets += 1
		if pkt.Length < BwdPacketLengthMin {
			BwdPacketLengthMin = pkt.Length
		}
	}
	BwdPacketLengthMean := float64(BwdTotPacketLength) / float64(BwdTotPackets)
	BwdPacketLengthStd := f.GetBwdPacketsStd(BwdTotPackets, BwdPacketLengthMean)
	if f.LastTime == f.StartTime {
		BwdPacketRate = 0
	} else {
		BwdPacketRate = float64(BwdTotPacketLength) / float64(f.LastTime-f.StartTime)
	}

	return BwdTotPacketLength, BwdTotPackets, BwdPacketLengthMin, BwdPacketLengthStd, BwdPacketLengthMean, BwdPacketRate
}
func (f Flow) GetBwdPacketsStd(BwdTotPackets int64, BwdPacketLengthMean float64) float64 {
	var sum float64 = 0
	for _, packet := range f.BwdPackets {
		diff := (float64(packet.Length) - BwdPacketLengthMean)
		sum += diff * diff
	}
	std := math.Sqrt(sum / float64(BwdTotPackets))
	return std
}
func (f Flow) GetFwdPacketStats() (int64, int64) {
	var FwdHeaderLength int64 = 0
	var FwdTotPackets int64 = 0

	for _, pkt := range f.FwdPackets {
		FwdHeaderLength += int64(pkt.HeaderLength)
		FwdTotPackets += 1
	}
	return FwdHeaderLength, FwdTotPackets
}
func (f Flow) GetPacketStats() (float64, float64) {
	var TotPackets int64 = 0
	var TotPacketsLength int64 = 0
	for _, pkt := range f.BwdPackets {
		TotPackets += 1
		TotPacketsLength += int64(pkt.Length)
	}
	for _, pkt := range f.FwdPackets {
		TotPackets += 1
		TotPacketsLength += int64(pkt.Length)
	}
	AveragePacketSize := float64(TotPacketsLength) / float64(TotPackets)

	PacketLengthStd := f.GetPacketsStd(TotPackets, AveragePacketSize)
	return AveragePacketSize, PacketLengthStd

}
func (f Flow) GetPacketsStd(TotPackets int64, PacketLengthMean float64) float64 {
	var sum float64 = 0
	for _, packet := range f.BwdPackets {
		diff := (float64(packet.Length) - PacketLengthMean)
		sum += diff * diff
	}
	for _, packet := range f.FwdPackets {
		diff := (float64(packet.Length) - PacketLengthMean)
		sum += diff * diff
	}
	std := math.Sqrt(sum / float64(TotPackets))
	return std
}

func (f Flow) GetIATStats() (int64, int64, int64) {
	if len(f.Flow_IAT_Arr) == 0 {
		return 0, 0, 0
	}
	FlowIATMin := f.Flow_IAT_Arr[0]
	FlowIATMax := f.Flow_IAT_Arr[0]
	var FlowIATTotal int64 = 0
	for _, IAT := range f.Flow_IAT_Arr {
		FlowIATTotal += IAT
		if IAT < FlowIATMin {
			FlowIATMin = IAT
		}
		if IAT > FlowIATMax {
			FlowIATMax = IAT
		}
	}
	return FlowIATMax, FlowIATMin, FlowIATTotal
}

func (f Flow) GetFlowDuration() int64 {
	return f.LastTime - f.StartTime
}

func (f Flow) GetLastCheckDuration() int64 {
	return time.Now().UnixMilli() - f.LastCheck
}

func (f Flow) GetFin(pkt Packet) bool {
	for _, flag := range pkt.TCPFlags {
		if flag == "FIN" {
			return true
		}

	}
	return false
}

func (f Flow) GetFullFeatures() map[string]string {
	BwdTotPacketLength, BwdTotPackets, BwdPacketLengthMin, BwdPacketLengthStd, BwdPacketLengthMean, BwdPacketRate := f.GetBwdPacketStats()
	FwdHeaderLength, FwdTotPackets := f.GetFwdPacketStats()
	AveragePacketSize, PacketLengthStd := f.GetPacketStats()
	FlowIATMax, FlowIATMin, FlowIATTotal := f.GetIATStats()
	fullFeatures := map[string]string{
		"Protocol":        f.Protocol,
		"MyDevice_ip":     f.MyDevice_ip,
		"MyDevice_port":   f.MyDevice_port,
		"Client_ip":       f.Client_ip,
		"Client_port":     f.Client_port,
		"StartTime":       strconv.FormatInt(f.StartTime, 10),
		"LastTime":        strconv.FormatInt(f.LastTime, 10),
		"Fin":             strconv.FormatBool(f.Fin),
		"InitWinBytesBwd": strconv.FormatUint(uint64(f.InitWinBytesBwd), 10),
		"InitWinBytesFwd": strconv.FormatUint(uint64(f.InitWinBytesFwd), 10),
		//Calculated Features
		"BwdTotPacketLength":  strconv.FormatInt(BwdTotPacketLength, 10),
		"BwdTotPackets":       strconv.FormatInt(BwdTotPackets, 10),
		"BwdPacketLengthMin":  strconv.FormatUint(uint64(BwdPacketLengthMin), 10),
		"BwdPacketLengthStd":  strconv.FormatFloat(BwdPacketLengthStd, 'f', -1, 64),
		"BwdPacketLengthMean": strconv.FormatFloat(BwdPacketLengthMean, 'f', -1, 64),
		"BwdPacketRate":       strconv.FormatFloat(BwdPacketRate, 'f', -1, 64),

		"FwdHeaderLength": strconv.FormatInt(FwdHeaderLength, 10),
		"FwdTotPackets":   strconv.FormatInt(FwdTotPackets, 10),
		// "MinSegSizeForward":  strconv.FormatInt(MinSegSizeForward, 10),
		"PacketLengthStd":   strconv.FormatFloat(PacketLengthStd, 'f', -1, 64),
		"AveragePacketSize": strconv.FormatFloat(AveragePacketSize, 'f', -1, 64),
		// "IdleMin":            strconv.FormatInt(IdleMin, 10),
		"FlowIATMin":   strconv.FormatInt(FlowIATMin, 10),
		"FlowIATMax":   strconv.FormatInt(FlowIATMax, 10),
		"FlowIATTotal": strconv.FormatInt(FlowIATTotal, 10),
		"FlowDuration": strconv.FormatInt(f.GetFlowDuration(), 10),
	}

	return fullFeatures
}
