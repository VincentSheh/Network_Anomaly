package features

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"net/http"
	"time"
)

// Top Feature Names: ['Destination_Port', 'Init_Win_bytes_backward', 'Init_Win_bytes_forward', 'Fwd_IAT_Min', 'Fwd_Header_Length', 'Flow_IAT_Min', 'Flow_Duration', 'Bwd_IAT_Min', 'Flow_Bytes/s', 'Bwd_Packet_Length_Std', 'Total_Length_of_Fwd_Packets', 'Packet_Length_Std', 'PSH_Flag_Count', 'Bwd_Packet_Length_Min', 'Total_Fwd_Packets', 'min_seg_size_forward', 'Total_Backward_Packets', 'Bwd_Packets/s', 'Fwd_Packet_Length_Max', 'Fwd_IAT_Mean']
type Flow struct {
	//Features Obtained from packet information
	Protocol     string
	MyDeviceIP   string //`json:"MyDeviceIP"`
	MyDevicePort string
	ClientIP     string
	ClientPort   string
	// Direction is bidirectional!

	//We dont need to import because it is within the same package
	FwdPackets []Packet `json:"-"`
	BwdPackets []Packet `json:"-"`

	StartTime int64
	LastTime  int64
	LastCheck int64
	Fin       int64
	Psh       int64

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
	Fwd_IAT_Arr  []int64
	Bwd_IAT_Arr  []int64
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
		f.MyDeviceIP = ipdst
		f.MyDevicePort = tcpdst
		f.ClientIP = ipsrc
		f.ClientPort = tcpsrc
	} else {
		f.MyDeviceIP = ipsrc
		f.MyDevicePort = tcpsrc
		f.ClientIP = ipdst
		f.ClientPort = tcpdst
	}
	f.StartTime = t
	f.LastTime = t
	f.LastCheck = t
	f.Fin = 0
	f.Psh = 0

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
		if f.StartTime != f.LastTime {
			f.Fwd_IAT_Arr = append(f.Fwd_IAT_Arr, packet.Time-f.LastTime)
		}

		//OUTBOUND PACKETS
	} else {
		f.FwdPackets = append(f.FwdPackets, packet)
		if f.InitWinBytesFwd == 0 {
			f.InitWinBytesFwd = packet.TCPWindow
		}
		if f.StartTime != f.LastTime {
			f.Bwd_IAT_Arr = append(f.Bwd_IAT_Arr, packet.Time-f.LastTime)
		}

	}
	f.GetFin(packet)

}

func (f Flow) GetBwdPacketStats() (int64, int64, int, float64, float64, float64, int64) {
	if len(f.BwdPackets) == 0 {
		return 0, 0, 0, 0, 0, 0, 0
	}
	BwdPacketLengthMin := f.BwdPackets[0].Length
	// max :=f.BwdPackets[0]
	var BwdTotPacketLength int64 = 0
	var BwdTotPackets int64 = 0
	var BwdPacketRate float64 = 0
	var BwdHeaderLength int64 = 0
	for _, pkt := range f.BwdPackets {
		BwdTotPacketLength += int64(pkt.Length)
		BwdHeaderLength += int64(pkt.HeaderLength)
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

	return BwdTotPacketLength, BwdTotPackets, BwdPacketLengthMin, BwdPacketLengthStd, BwdPacketLengthMean, BwdPacketRate, BwdHeaderLength
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
func (f Flow) GetFwdPacketStats() (int64, int64, float64) {
	var FwdHeaderLength int64 = 0
	var FwdTotPackets int64 = 0
	var FwdPacketRate float64 = 0
	for _, pkt := range f.FwdPackets {
		FwdHeaderLength += int64(pkt.HeaderLength)
		FwdTotPackets += 1
	}
	flowDuration := f.GetFlowDuration()
	FwdPacketRate = float64(FwdTotPackets) / float64(flowDuration)
	return FwdHeaderLength, FwdTotPackets, FwdPacketRate
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

func (f Flow) GetIATStats() (int64, int64, int64, int64) {
	if len(f.Flow_IAT_Arr) == 0 {
		return 0, 0, 0, 0
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
	//Fwd IAT
	if len(f.Fwd_IAT_Arr) == 0 {
		return FlowIATMax, FlowIATMin, FlowIATTotal, 0
	}
	fwd_min_IAT := f.Fwd_IAT_Arr[0]
	for _, IAT := range f.Fwd_IAT_Arr {
		if IAT < fwd_min_IAT {
			fwd_min_IAT = IAT
		}
	}

	return FlowIATMax, FlowIATMin, FlowIATTotal, fwd_min_IAT
}

func (f Flow) GetFlowDuration() int64 {
	return f.LastTime - f.StartTime
}

func (f Flow) GetLastCheckDuration() int64 {
	return time.Now().UnixMilli() - f.LastCheck
}

func (f *Flow) GetFin(pkt Packet) {
	// isFin, isPsh := false, false
	for _, flag := range pkt.TCPFlags {
		if flag == "FIN" {
			f.Fin += 1
		}
		if flag == "PSH" {
			f.Psh += 1
		}

	}
	// return isFin, isPsh
}

func (f Flow) GetFullFeatures() map[string]interface{} {
	// BwdTotPacketLength, BwdTotPackets, BwdPacketLengthMin, BwdPacketLengthStd, BwdPacketLengthMean, BwdPacketRate := f.GetBwdPacketStats()
	BwdTotPacketLength,
		BwdTotPackets,
		BwdPacketLengthMin,
		_,
		BwdPacketLengthMean,
		BwdPacketRate,
		GetBwdPacketStats := f.GetBwdPacketStats()

	FwdHeaderLength, FwdTotPackets, FwdPacketRate := f.GetFwdPacketStats()
	AveragePacketSize, PacketLengthStd := f.GetPacketStats()

	FlowIATMax, FlowIATMin, FlowIATTotal, fwd_min_IAT := f.GetIATStats()
	// _, FlowIATMin, _ := f.GetIATStats()

	fullFeatures := map[string]interface{}{
		"Init_Win_bytes_forward":  uint64(f.InitWinBytesFwd),
		"Bwd Packets/s":           BwdPacketRate,
		"Init_Win_bytes_backward": uint64(f.InitWinBytesBwd),
		"Flow Duration":           f.GetFlowDuration(),
		"Packet Length Std":       PacketLengthStd,
		"Destination Port":        f.ClientPort,
		// "MinSegSizeForward":			 MinSegSizeForward,
		"Average Packet Size": AveragePacketSize,

		"Total Length of Bwd Packets": BwdTotPacketLength,
		"Bwd Packet Length Min":       uint64(BwdPacketLengthMin),
		"Fwd Header Length":           FwdHeaderLength,
		"Bwd Header Length":           GetBwdPacketStats,
		"Total Backward Packets":      BwdTotPackets,
		"Total Length of Fwd Packets": FwdTotPackets,
		"Bwd Packet Length Mean":      BwdPacketLengthMean,
		"Fwd Packets/s":               FwdPacketRate,

		// "Protocol":        f.Protocol,
		// "MyDeviceIP":      f.MyDeviceIP,
		// "MyDevicePort":    f.MyDevicePort,
		// "ClientIP":        f.ClientIP,
		// "StartTime":       f.StartTime,
		// "LastTime":        f.LastTime,
		// "Fin":             f.Fin,
		// //Calculated Features
		// "BwdPacketLengthStd":  BwdPacketLengthStd,
		// // "IdleMin":            strconv.FormatInt(IdleMin, 10),
		"Flow IAT Min":   FlowIATMin,
		"Flow IAT Max":   FlowIATMax,
		"Flow IAT Total": FlowIATTotal,
		"Fwd IAT Min":    fwd_min_IAT,
		"PSH Flag Count": f.Psh,
	}

	return fullFeatures
}

// Send detection
func (f *Flow) SendFlowData() bool {
	//Update lastCheck
	f.LastCheck = time.Now().UnixMilli()
	jsonData, err := json.Marshal(f.GetFullFeatures())
	features := f.GetFullFeatures()
	for key, value := range features {
		fmt.Printf("%s: %v\n", key, value)
	}
	if err != nil {
		fmt.Println(err)
		return false
	}
	// detectorUrl := "http://192.168.50.221:3001/detect"
	detectorUrl := "http://idsmodel.com/detect"
	// detectorUrl := "http://127.0.0.1:4000/detect"
	// detectorUrl := "http://ids-model-service.default.svc.cluster.local:1935/detect"
	// detectorUrl := "http://10.102.223.78:1935/detect"

	req, err := http.NewRequest("POST", detectorUrl, bytes.NewBuffer(jsonData))
	if err != nil {
		fmt.Println(err)
		return false
	}
	req.Header.Set("Content-Type", "application/json")

	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		fmt.Println(err)
		return false
	}
	defer resp.Body.Close()

	body, _ := io.ReadAll(resp.Body)
	fmt.Println("Response:", string(body))

	// Unmarshal JSON data
	var response Response
	err = json.Unmarshal(body, &response)
	if err != nil {
		fmt.Println("Error unmarshaling JSON:", err)
		return false
	}
	fmt.Println("IsMalicious:", response.IsMalicious)
	return response.IsMalicious

}

type Response struct {
	IsMalicious bool `json:"isMalicious"`
}
