package main

import (
	"crypto/sha1"
	"encoding/hex"
	"fmt"
	"io/ioutil"
	"net/http"
	"net/url"
	"sync"

	"github.com/howeyc/fsnotify"
)

var htmlFile []byte
var mu sync.Mutex

func GetIndexFile() []byte {

	mu.Lock()
	res := make([]byte, len(htmlFile))
	copy(res, htmlFile)
	mu.Unlock()

	return res
}

func GetChecksum(apiCall, query, sharedSecret string) string {
	data := apiCall + query + sharedSecret
	checksum := sha1.Sum([]byte(data))

	fmt.Println(apiCall, " + ", query, " + ", sharedSecret, " = ", hex.EncodeToString(checksum[:]))

	return hex.EncodeToString(checksum[:])
}

func rootCall(w http.ResponseWriter, r *http.Request) {
	r.URL.Query()

	message := GetIndexFile()

	w.Write(message)
}

func actionHandler(w http.ResponseWriter, r *http.Request) {
	r.ParseForm()
	var server string
	var sharedsecret string
	var call string
	var query url.Values

	for k, v := range r.Form {
		fmt.Println(k, " -> ", v)
		switch k {
		case "server":
			server = v[0]
		case "sharedsecret":
			sharedsecret = v[0]
		case "call":
			call = v[0]
			if call == "root" {
				call = ""
			}
		case "query":
			q := v[0]
			query, _ = url.ParseQuery(q)
		}
	}

	var encodedQuery string
	if call == "create" {
		encodedQuery = ""
	} else {
		encodedQuery = query.Encode()
	}
	response, contentType := postCreate(call, server, sharedsecret, encodedQuery, query)
	w.Header().Set("Content-Type", contentType)
	w.Write(response)
}

// The BBB uses the empty query to calculate the checksum, thus the checksum for post
// requests will always be the same for a given call
func postCreate(apiCall string, server string, SharedSecret string, query string, u url.Values) ([]byte, string) {
	checksum := GetChecksum(apiCall, query, SharedSecret)
	serverURL := server + apiCall
	if apiCall != "create" {
		serverURL += "?" + query + "checksum=" + checksum
	}

	u.Add("checksum", checksum)

	fmt.Println("POST query: ", serverURL)

	rs, err := http.PostForm(serverURL, u)
	var contentType string

	if err != nil {
		fmt.Println(err)
	} else {
		contentType = rs.Header.Get("Content-Type")
		r, _ := ioutil.ReadAll(rs.Body)
		return r, contentType
	}
	return nil, contentType
}

func CreateWatcher() {
	watcher, err := fsnotify.NewWatcher()
	if err != nil {
		fmt.Println("Event Watcher error:", err)
	}
	defer watcher.Close()

	done := make(chan bool)

	//
	go func() {
		for {
			select {
			// watch for events
			case event := <-watcher.Event:
				if event.IsModify() {
					// Reload file
					fmt.Println("Reloading index.html")
					mu.Lock()
					htmlFile, _ = ioutil.ReadFile("./index.html")
					mu.Unlock()
				}
				// watch for errors
			case err := <-watcher.Error:
				fmt.Println("Event Watcher error: ", err)
			}
		}
	}()

	if err = watcher.Watch("./index.html"); err != nil {
		fmt.Println("Event Watcher error:", err)
	}

	<-done
}

func sha1Js(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/javascript")
	bytes, _ := ioutil.ReadFile("sha1.js")
	w.Write(bytes)
}

func main() {
	htmlFile, _ = ioutil.ReadFile("./index.html")
	go CreateWatcher()
	http.HandleFunc("/", rootCall)
	http.HandleFunc("/action", actionHandler)
	http.HandleFunc("/sha1.js", sha1Js)
	if err := http.ListenAndServe(":8090", nil); err != nil {
		panic(err)
	}
}
