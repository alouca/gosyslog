package main

import (
	"encoding/json"
	"html/template"
	"io"
	"net/http"
	"strconv"
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

func startServer(port string) {
	http.Handle("/static/", http.StripPrefix("/static/", http.FileServer(http.Dir("web/static/"))))
	http.HandleFunc("/data", DataHandler)
	http.HandleFunc("/", IndexHandler)
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
	t, e := template.ParseGlob("web/templates/*.tmpl")

	if e != nil {
		l.Fatal("Unable to parse templates: %s\n", e.Error())
	}

	e = t.Execute(w, nil)

	if e != nil {
		l.Fatal("Error executing template: %s\n", e.Error())
	}
}
