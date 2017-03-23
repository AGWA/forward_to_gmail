// Copyright (C) 2016-2017 Andrew Ayer
//
// Permission is hereby granted, free of charge, to any person obtaining a
// copy of this software and associated documentation files (the "Software"),
// to deal in the Software without restriction, including without limitation
// the rights to use, copy, modify, merge, publish, distribute, sublicense,
// and/or sell copies of the Software, and to permit persons to whom the
// Software is furnished to do so, subject to the following conditions:
//
// The above copyright notice and this permission notice shall be included
// in all copies or substantial portions of the Software.
//
// THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
// IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
// FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL
// THE AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR
// OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE,
// ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
// OTHER DEALINGS IN THE SOFTWARE.
//
// Except as contained in this notice, the name(s) of the above copyright
// holders shall not be used in advertising or otherwise to promote the
// sale, use or other dealings in this Software without prior written
// authorization.

package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"flag"
	"fmt"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"io"
	"io/ioutil"
	"net/http"
	"os"
)

const (
	// from sysexits.h
	EX_OK       = 0
	EX_DATAERR  = 65
	EX_SOFTWARE = 70
	EX_IOERR    = 74
	EX_TEMPFAIL = 75
	EX_CONFIG   = 78
)

var getUrl = flag.Bool("get-url", false, "Get the authorization URL")
var getTokenAuthCode = flag.String("get-token", "", "Get a token for the given authorization code")
var inbox = flag.Bool("inbox", false, "Send message to the INBOX")

func isSuccessful(statusCode int) bool {
	return statusCode >= 200 && statusCode <= 299
}

func isTemporaryError(statusCode int) bool {
	return (statusCode >= 500 && statusCode <= 500) || statusCode == 429 || statusCode == 403
}

func makeConfig() *oauth2.Config {
	conf := &oauth2.Config{
		ClientID:     os.Getenv("GMAIL_CLIENT_ID"),
		ClientSecret: os.Getenv("GMAIL_CLIENT_SECRET"),
		Scopes: []string{
			"https://www.googleapis.com/auth/gmail.insert",
		},
		Endpoint:    google.Endpoint,
		RedirectURL: "urn:ietf:wg:oauth:2.0:oob",
	}
	if conf.ClientID == "" {
		fmt.Fprintf(os.Stderr, "forward_to_gmail: $GMAIL_CLIENT_ID not set\n")
		os.Exit(EX_CONFIG)
	}
	if conf.ClientSecret == "" {
		fmt.Fprintf(os.Stderr, "forward_to_gmail: $GMAIL_CLIENT_SECRET not set\n")
		os.Exit(EX_CONFIG)
	}
	return conf
}

func makeClient(conf *oauth2.Config) *http.Client {
	refreshToken := os.Getenv("GMAIL_TOKEN")
	if refreshToken == "" {
		fmt.Fprintf(os.Stderr, "forward_to_gmail: $GMAIL_TOKEN not set\n")
		os.Exit(EX_CONFIG)
	}
	return conf.Client(oauth2.NoContext, &oauth2.Token{RefreshToken: refreshToken})
}

type message struct {
	LabelIds []string `json:"labelIds"`
	Raw      string   `json:"raw"`
}

func makeMessage(rawMesg []byte) *message {
	if bytes.HasPrefix(rawMesg, []byte("From ")) {
		nl := bytes.IndexByte(rawMesg, '\n')
		if nl == -1 {
			fmt.Fprintf(os.Stderr, "forward_to_gmail: Malformed message read from stdin: no newline\n")
			os.Exit(EX_DATAERR)
		}
		rawMesg = rawMesg[nl+1:]
	}
	mesg := &message{
		LabelIds: []string{"UNREAD"},
		Raw:      base64.URLEncoding.EncodeToString(rawMesg),
	}
	if *inbox {
		mesg.LabelIds = append(mesg.LabelIds, "INBOX")
	}
	return mesg
}

func main() {
	flag.Parse()

	conf := makeConfig()

	if *getUrl {
		fmt.Println(conf.AuthCodeURL("", oauth2.AccessTypeOffline))
		os.Exit(EX_OK)
	} else if *getTokenAuthCode != "" {
		token, err := conf.Exchange(oauth2.NoContext, *getTokenAuthCode)
		if err != nil {
			fmt.Fprintf(os.Stderr, "forward_to_gmail: Error obtaining token: %s\n", err)
			os.Exit(1)
		}
		fmt.Println(token.RefreshToken)
		os.Exit(EX_OK)
	} else {
		client := makeClient(conf)

		rawMesg, err := ioutil.ReadAll(os.Stdin)
		if err != nil {
			fmt.Fprintf(os.Stderr, "forward_to_gmail: Error reading message from stdin: %s\n", err)
			os.Exit(EX_IOERR)
		}
		mesg := makeMessage(rawMesg)

		var requestBody bytes.Buffer
		if err := json.NewEncoder(&requestBody).Encode(mesg); err != nil {
			fmt.Fprintf(os.Stderr, "forward_to_gmail: Error encoding message: %s\n", err)
			os.Exit(EX_SOFTWARE)
		}
		response, err := client.Post("https://www.googleapis.com/gmail/v1/users/me/messages/import", "application/json", &requestBody)
		if err != nil {
			fmt.Fprintf(os.Stderr, "forward_to_gmail: Error communicating with Gmail API endpoint: %s\n", err)
			os.Exit(EX_TEMPFAIL)
		}

		if isSuccessful(response.StatusCode) {
			io.Copy(ioutil.Discard, response.Body)
			response.Body.Close()
			os.Exit(EX_OK)
		} else {
			var responseBody bytes.Buffer
			io.Copy(&responseBody, response.Body)
			response.Body.Close()

			fmt.Fprintf(os.Stderr, "forward_to_gmail: HTTP error %s from Gmail API: %s\n", response.StatusCode, responseBody.String())

			if isTemporaryError(response.StatusCode) {
				os.Exit(EX_TEMPFAIL)
			} else {
				os.Exit(EX_SOFTWARE)
			}
		}
	}
}
