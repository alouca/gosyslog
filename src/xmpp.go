package main

import (
	"github.com/mattn/go-xmpp"
)

type XmppInterface struct {
	SendChannel	chan xmpp.Chat
	ReceiveChannel	chan xmpp.Chat
}

func (x *XmppInterface) Connect() {
	username := c.GetString("xmpp.username")
	password := c.GetString("xmpp.password")
	server := c.GetString("xmpp.server")

	l.Debug("XMPP Interface - User/Pass: %s/%s\n", username, password)

	x.SendChannel = make(chan xmpp.Chat)
	x.ReceiveChannel = make(chan xmpp.Chat)

	talk, err := xmpp.NewClient(server, username, password)

	if err != nil {
		l.Fatal("Error connecting to google talk: %s\n", err.Error())
	}

	go func() {
		for {
			chat, err := talk.Recv()
			if err != nil {
				l.Fatal("Error receiving data from google talk: %s\n", err.Error())
			}
			x.ReceiveChannel <- chat
		}
	}()
	// xmpp.Chat{Remote: tokens[0], Type: "chat", Text: tokens[1]}
	go func() {
		for {
			select {
			case chat := <-x.SendChannel:
				talk.Send(chat)
			}
		}
	}()
}

func (x *XmppInterface) Chat(remote, text string) {
	x.SendChannel <- xmpp.Chat{Remote: remote, Type: "chat", Text: text}
}
