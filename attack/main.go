package main

import (
	"attack/dos"
	"attack/portscan"
	"fmt"
	"net"
	"os"
	"time"

	"github.com/tatsushid/go-fastping"
)

//	type PortScanner struct {
//		ip   string
//		lock *semaphore.Weighted
//	}
func pingIP(ip string) bool {
	var isValidIp bool = false
	p := fastping.NewPinger()
	ra, err := net.ResolveIPAddr("ip4:icmp", ip)
	if err != nil {
		fmt.Println(err)
		os.Exit(1)
	}
	p.AddIPAddr(ra)
	p.OnRecv = func(addr *net.IPAddr, rtt time.Duration) {
		fmt.Printf("IP Addr: %s receive, RTT: %v\n", addr.String(), rtt)
		isValidIp = true
	}
	p.OnIdle = func() {
		if isValidIp {
			fmt.Println("The IP address is valid and reachable.")
		} else {
			fmt.Println("The IP address is not reachable.")
		}
		fmt.Println("Finish")
	}
	err = p.Run()

	if err != nil {
		fmt.Println(err)
	}
	return isValidIp
}
func main() {
	//Get User Input
	// reader := bufio.NewReader(os.Stdin)
	// fmt.Printf("Which Attack do u want to perform ")
	// att, _ := reader.ReadString('\n')
	// att = strings.TrimSpace(att)
	// reader = bufio.NewReader(os.Stdin)
	// fmt.Printf("Specify a target host")
	// host, _ := reader.ReadString('\n')
	// host = strings.TrimSpace(host)
	target := "127.0.0.1"
	att := "portscan"
	// PING the ip
	isValidIp := pingIP((target))
	if !isValidIp {
		return
	}

	if att == "dos" { //This is just DoS not dos
		n_workers := 100
		fmt.Printf("Performing dos on %s with  %d workers\n", target, n_workers)
		dos.Run_dos(n_workers, target)

	}
	if att == "portscan" {

		fmt.Printf("Performing Portscan on %s\n", target)
		portscan.RunPortscan(target)
		// Perform Pinging

	}
}
