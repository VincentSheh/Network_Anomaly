package utils

import (
	"log"
	"os/exec"
)

func CleanIPTables() {

}

func WhiteListIP(string) {
	// exec.Command()
}

func BlackListIP(ip string, port string) {
	cmd := exec.Command("sudo", "iptables", "-I", "TEST", "-s", ip, "--destination-port", port, "-j", "DROP") // Add to custom chain
	err := cmd.Run()
	if err != nil {
		log.Fatalf("Failed to execute iptables command: %s", err)
	}
}
