package main

import (
	"encoding/json"
	"github.com/mattn/go-session-manager"
	"html/template"
	"io"
	"net/http"
	"strconv"
	"strings"
)

var (
	t *template.Template
)

type SyslogMessage struct {
	Id		int
	Source		string
	Timestamp	int
	Facility	int
	Severity	int
	Message		string
}

type JSONLiveData struct {
	Messages []SyslogMessage
}

var (
	manager *session.SessionManager
)

func startServer(port string) {
	manager = session.NewSessionManager(nil)

	manager.OnStart(func(session *session.Session) {
		l.Debug("Session Manager: Started a new session.\n")
	})
	manager.OnEnd(func(session *session.Session) {
		l.Debug("Session Manager: Destroyed a session.\n")
	})
	manager.SetTimeout(10)

	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static/"))))
	http.HandleFunc("/data", DataHandler)
	http.HandleFunc("/", IndexHandler)
	http.HandleFunc("/login", LoginHandler)
	var e error

	t, e = template.ParseGlob("web/templates/*.tmpl")

	if e != nil {
		l.Fatal("Unable to parse templates: %s\n", e.Error())
	}

	e = http.ListenAndServe(port, nil)

	if e != nil {
		l.Fatal("Unable to start embeeded webserver: %s\n", e.Error())
	}
}

type LoginFormData struct {
	NotificationTitle	string
	Notification		string
}

func LoginHandler(w http.ResponseWriter, req *http.Request) {
	session := manager.GetSession(w, req)
	t, e := template.ParseGlob("web/templates/*.tmpl")
	if e != nil {
		l.Fatal("Unable to parse templates: %s\n", e.Error())
	}

	err := req.ParseForm()

	if err != nil {
		l.Fatal("Unable to parse HTTP Form: %s\n", err.Error())
		return
	}

	username := strings.ToLower(req.FormValue("username"))
	password := req.FormValue("password")

	if username != "" {
		if user, ok := settings.Users[username]; ok {
			if user.Password == password {
				session.Value = make(map[string]string)
				http.Redirect(w, req, "/", http.StatusFound)
			} else {
				e = t.ExecuteTemplate(w, "login", LoginFormData{"Error Logging in", "No such username/password combination exists."})

			}
		}
	} else {
		e = t.ExecuteTemplate(w, "login", nil)

	}

	if e != nil {
		l.Fatal("Error executing template: %s\n", e.Error())
	}
}

func DataHandler(w http.ResponseWriter, req *http.Request) {
	err := req.ParseForm()

	if err != nil {
		l.Fatal("Unable to parse HTTP Form: %s\n", err.Error())
	}

	lastid, err := strconv.Atoi(req.FormValue("lastid"))
	sample, err := strconv.Atoi(req.FormValue("sample"))

	if sample <= 0 {
		sample = 100
	}

	rows, err := db.Query("select * from syslog where id > ? ORDER BY timestamp DESC LIMIT ?", lastid, sample)

	if err != nil {
		l.Fatal("Unable to fetch data: %s\n", err.Error())
		return
	}

	var data JSONLiveData

	data.Messages = make([]SyslogMessage, 0, 100)

	for rows.Next() {
		var msg SyslogMessage
		err := rows.Scan(&msg.Id, &msg.Source, &msg.Timestamp, &msg.Facility, &msg.Severity, &msg.Message)
		if err != nil {
			l.Fatal("Unable to scan data: %s\n", err.Error())
			return
		}
		data.Messages = append(data.Messages, msg)

	}

	jsonData, e := json.Marshal(data)

	if e != nil {
		l.Fatal("Error marshalling JSON: %s\n", e.Error())
	}

	l.Debug("Marshalled JSON: %s\n", string(jsonData))

	io.WriteString(w, string(jsonData))
}

func IndexHandler(w http.ResponseWriter, req *http.Request) {
	session := manager.GetSession(w, req)

	// Check if user is logged in
	if session.Value == nil {
		http.Redirect(w, req, "/login", http.StatusFound)
		return
	}

	t, e := template.ParseGlob("web/templates/*.tmpl")

	if e != nil {
		l.Fatal("Unable to parse templates: %s\n", e.Error())
	}

	e = t.ExecuteTemplate(w, "index", nil)

	if e != nil {
		l.Fatal("Error executing template: %s\n", e.Error())
	}
}
