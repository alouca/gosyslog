package main

import (
	//	"fmt"
	"net"
	"strings"
	"logger"
	"time"
	"os"
	"strconv"
	"database/sql"
	_ "github.com/ziutek/mymysql/godrv"
)

const (
	KERNEL	= iota
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
	EMERGENCY	= iota
	ALERT
	CRITICAL
	ERROR
	WARNING
	NOTICE
	INFORMATIONAL
	DEBUG
)

var (
	l	*logger.Logger
	db	*sql.DB
)

func main() {
	// Init the logger
	l = logger.CreateLogger(true, true)

	go startServer(":8888")

	pc, err := net.ListenPacket("udp4", ":514")
	defer pc.Close()

	if err != nil {
		l.Fatal("Error on listen: %s\n", err.Error())
		os.Exit(1)
	}

	// Connect to mysql database
	db, err = sql.Open("mymysql", "gosyslog/root/")

	if err != nil {
		l.Fatal("Error on mysql connect: %s\n", err.Error())
		os.Exit(1)
	}

	for {
		var buffer [1500]byte
		readBytes, addr, err := pc.ReadFrom(buffer[0:])

		if err != nil {
			l.Fatal("Error on read: %s\n", err.Error())
			os.Exit(1)
		}

		l.Debug("Read total %d bytes from %s\n", readBytes, addr.String())
		message := string(buffer[0:readBytes])
		// Retrieve Priority
		priority := message[strings.Index(message, "<")+1 : strings.Index(message, ">")]
		pri, err := strconv.Atoi(priority)

		facility := pri / 8
		severity := pri % 8

		l.Debug("Priority: %s - Facility: %d Severity: %d\n", priority, facility, severity)
		l.Debug("%s\n", message)

		ipAddress := addr.String()
		message = strings.TrimSpace(message[strings.Index(message, ":")+2:])

		db.Exec("insert into syslog (source, timestamp, facility, severity, message) VALUES (?, ?, ?, ?, ?)", ipAddress[0:strings.Index(ipAddress, ":")], time.Now().Unix(), facility, severity, message)

	}
}
