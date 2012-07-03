package main

import (
	"fmt"
	"net"
	"strings"
	"os"
	"strconv"
)

const (
	KERNEL = iota
	USERLEVEL
	MAIL
	SYSTEM
	SECURITY
	SYSLOG
	LINE
	NEWS
	CLOCK
	SECURITY2
	FTP
	NTP
	AUDIT
	FACILITY_ALERT
	CLOCK2
	LOCAL0
	LOCAL1
	LOCAL2
	LOCAL3
	LOCAL4
	LOCAL5
	LOCAL6
	LOCAL7
)

const (
	EMERGENCY = iota
	ALERT
	CRITICAL
	ERROR
	WARNING
	NOTICE
	INFORMATIONAL
	DEBUG
)

func main() {
	pc, err := net.ListenPacket("udp4", ":514")

	if err != nil {
		fmt.Printf("Error on listen: %s\n", err.String())
		os.Exit(1)
	}

	for {
		var buffer [1500]byte
		readBytes, addr, err := pc.ReadFrom(buffer[0:])

		if err != nil {
			fmt.Printf("Error on read: %s\n", err.String())
			os.Exit(1)
		}

		fmt.Printf("Read total %d bytes from %s\n", readBytes, addr.String())
		message := string(buffer[0:readBytes])
		// Retrieve Priority
		priority := message[strings.Index(message, "<")+1:strings.Index(message, ">")]
		pri, err := strconv.Atoi(priority)
		
		facility := pri / 8
		severity := pri % 8
		
		fmt.Printf("Priority: %s - Facility: %d Severity: %d\n", priority, facility, severity)
		fmt.Printf("%s\n", message)

	}

}
