package main

import (
	"fmt"
	"net"
	"strings"
	"logger"
	"time"
	"encoding/json"
	"os"
	"io/ioutil"
	"flag"
	"strconv"
	"database/sql"
	"config"
	"regexp"
	_ "github.com/ziutek/mymysql/godrv"
)

type SyslogFilter struct {
	Expression	string
	Action		string
	RegExp		*regexp.Regexp	`json:"-"`
}

type SyslogAccountSettings struct {
	Username	string
	Password	string
	XmppEnabled	bool
	XmppReceipient	string
	EmailEnabled	bool
	EmailAddress	string
	// Filters
	Filters	map[string][]SyslogFilter
}

type SyslogSettings struct {
	Users map[string]SyslogAccountSettings
}

type SyslogEvent struct {
	Source		string
	Timestamp	int64
	Facility	int
	Severity	int
	Message		string
}

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
	l			*logger.Logger
	db			*sql.DB
	c			*config.Config
	settings		SyslogSettings
	configConfigFile	string
	xmppConn		*XmppInterface
)

func init() {
	flag.StringVar(&configConfigFile, "config", "gosyslog.json", "Specify the GoSyslog Server Configuration File")
	flag.Parse()

	// Load the configuration file
	c = config.LoadConfigFromFile(configConfigFile)

	verbose := c.GetBool("logger.verbose")
	debug := c.GetBool("logger.debug")
	logOut := c.GetString("logger.output")

	if logOut == "stdout" {
		l = logger.CreateLogger(verbose, debug)
	} else {
		l = logger.CreateLoggerWithFile(verbose, debug, logOut)
	}
}

func loadSettings() {
	// Load JSON Settings
	settingsPath := c.GetString("settings.path")
	file, err := os.OpenFile(settingsPath, os.O_RDWR, 0666)

	if err != nil {
		l.Fatal("Unable to open settings file: %s\n", err.Error())
	}

	// Load & parse the settings file
	data, err := ioutil.ReadAll(file)

	if err != nil {
		l.Fatal("Unable to read settings file: %s\n", err.Error())
	}

	err = json.Unmarshal(data, &settings)

	if err != nil {
		l.Fatal("Unable to parse settings file: %s\n", err.Error())
	}
}

func main() {
	// Load Settings
	loadSettings()
	/*
		// Init the regexp data
		var filters SyslogFilters
		filters.Filters = make(map[string]SyslogFilter)
		filters.Filters["172.17.2.1"] = SyslogFilter{"/POWERSUPPLYFANBAD/", "IGNORE", nil}

		user := SyslogAccountSettings{"alouca", "q1w2e3", true, "alouca@xmpp.cablenet-as.net", true, "a.louca@cablenetcy.net", filters}

		var settings SyslogSettings
		settings.Users = make(map[string]SyslogAccountSettings)
		settings.Users["alouca"] = user

		res, err := json.Marshal(settings)

		if err != nil {
			l.Error("Unable to marshal filters: %s\n", err.Error())
		} else {
			l.Debug("Encoded filters: %s\n", string(res))
		}*/

	go startServer(":8888")

	pc, err := net.ListenPacket("udp4", ":514")
	defer pc.Close()

	xmppConn = new(XmppInterface)
	xmppConn.Connect()

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
			//os.Exit(1)
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

		go handleEventActions(SyslogEvent{ipAddress[0:strings.Index(ipAddress, ":")], time.Now().Unix(), facility, severity, message})

	}
}

func handleEventActions(event SyslogEvent) {
	db.Exec("insert into syslog (source, timestamp, facility, severity, message) VALUES (?, ?, ?, ?, ?)", event.Source, event.Timestamp, event.Facility, event.Severity, event.Message)
	go publishAlerts(event)

}

func publishAlerts(event SyslogEvent) {
	for _, user := range settings.Users {
		go processFilter(user, event)
	}

}

func processFilter(user SyslogAccountSettings, event SyslogEvent) {
	// If we have filters for this particular source, evaluate them
	if filter, ok := user.Filters[event.Source]; ok {
		for _, f := range filter {
			l.Debug("Trying to compile %s\n", f.Expression)
			f.RegExp = regexp.MustCompile(f.Expression)
			if f.RegExp != nil {
				if f.RegExp.Match([]byte(event.Message)) {
					l.Debug("Expression %s matched on %s\n", f.Expression, event.Message)
					// If expression matches, check action plan
					switch f.Action {
					case "IGNORE":
						l.Debug("Ignoring event from %s for user %s\n", event.Source, user.Username)
						return
					case "ACCEPT":
						l.Debug("Accepting event from %s for user %s\n", event.Source, user.Username)
						notifyUser(user, event)
						return
					}
				}
			} else {
				l.Debug("Compilation of expression %s has failed.", f.Expression)
			}
		}
	}
	// Default action (if not returned before), is to notify the user
	notifyUser(user, event)

}

func notifyUser(user SyslogAccountSettings, event SyslogEvent) {
	// Default action is ACCEPT, so pass the events on
	if user.XmppEnabled {
		l.Debug("Chatting to: %s\n", user.XmppReceipient)
		xmppConn.Chat(user.XmppReceipient, fmt.Sprintf("%s: %s", event.Source, event.Message))
	}
}
