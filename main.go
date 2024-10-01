package main

import (
	"crypto/rand"
	"crypto/subtle"
	"encoding/base32"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"log"
	"maps"
	"net/http"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"
)

var (
	authToken string
	filename  string
	mu        sync.Mutex
	checkins  = make(map[string]time.Time)
	keyRe     = regexp.MustCompile(`^[a-zA-Z0-9._-]+-(\d+[hms])$`)
)

func load() {
	data, err := os.ReadFile(filename)
	if err != nil {
		if os.IsNotExist(err) {
			log.Printf("no watchdogd database file found, starting with an empty database.")
			return
		} else {
			log.Fatalf("error loading watchdogd database: %v", err)
		}
	}

	err = json.Unmarshal(data, &checkins)
	if err != nil {
		log.Printf("corrupted watchdogd database file, starting with an empty database.")
	}
}

func save() {
	if filename == "" {
		return
	}
	mu.Lock()
	m := maps.Clone(checkins)
	mu.Unlock()

	data := must(json.MarshalIndent(m, "", "  "))
	err := os.WriteFile(filename, data, 0644)
	if err != nil {
		log.Fatalf("watchdogd saving failed: %v", err)
	}
}

func parse(key string) (time.Duration, bool) {
	m := keyRe.FindStringSubmatchIndex(key)
	if m == nil {
		return 0, false
	}
	return must(time.ParseDuration(key[m[2]:m[3]])), true
}

func authMiddleware(handler http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		token := r.Header.Get("Authorization")
		if token == "" {
			token = r.URL.Query().Get("token")
		} else {
			var ok bool
			token, ok = strings.CutPrefix(token, "Bearer ")
			if !ok {
				http.Error(w, "Invalid Authorization format", http.StatusBadRequest)
				return
			}
		}

		if subtle.ConstantTimeCompare([]byte(authToken), []byte(token)) != 1 {
			http.Error(w, "Unauthorized", http.StatusUnauthorized)
			return
		}

		handler(w, r)
	}
}

func checkinHandler(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	if _, ok := parse(key); !ok {
		http.Error(w, "Invalid key", http.StatusBadRequest)
		return
	}

	now := time.Now().UTC()
	mu.Lock()
	checkins[key] = now
	mu.Unlock()

	go save()
	w.WriteHeader(http.StatusNoContent)
}

func statusHandler(w http.ResponseWriter, r *http.Request) {
	key := r.PathValue("key")
	dur, ok := parse(key)
	if !ok {
		http.Error(w, "Invalid key", http.StatusBadRequest)
		return
	}

	mu.Lock()
	lastCheckin := checkins[key]
	mu.Unlock()

	now := time.Now()
	w.Header().Set("Content-Type", "text/plain")
	printStatus(w, key, dur, lastCheckin, now)
}

func listHandler(w http.ResponseWriter, r *http.Request) {
	mu.Lock()
	m := maps.Clone(checkins)
	mu.Unlock()

	w.Header().Set("Content-Type", "text/plain")
	fmt.Fprintf(w, "watchdogd has %d keys\n", len(m))
	now := time.Now()
	for key, lastCheckin := range m {
		dur, _ := parse(key)
		printStatus(w, key, dur, lastCheckin, now)
	}
}

func printStatus(w io.Writer, key string, dur time.Duration, lastCheckin, now time.Time) {
	if lastCheckin.IsZero() {
		fmt.Fprintf(w, "%s NEVER ALARM\n", key)
		return
	}
	since := now.Sub(lastCheckin)
	var status string
	if since > dur {
		status = "ALARM"
	} else {
		status = "OKAY"
	}
	fmt.Fprintf(w, "%s %s %.0fh %.0fm %.0fs %s\n", key, lastCheckin.Format(time.RFC3339), since.Hours(), since.Minutes(), since.Seconds(), status)
}

func main() {
	log.SetFlags(0)
	log.SetOutput(os.Stderr)

	var listenAddr string
	flag.StringVar(&filename, "f", "", "path to JSON database file")
	flag.StringVar(&authToken, "t", "", "bearer token for authorization")
	flag.StringVar(&listenAddr, "l", ":8080", "listen address")
	flag.Parse()

	if authToken == "" {
		var token [32]byte
		must(rand.Read(token[:]))
		authToken = base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(token[:])
		log.Printf("auth token not specified, using a random token: %s", authToken)
	}

	if filename == "" {
		log.Printf("no filename specified, running an in-memory server.")
	} else {
		load()
	}

	mux := http.NewServeMux()
	mux.HandleFunc("POST /{key}", authMiddleware(checkinHandler))
	mux.HandleFunc("GET /{key}", statusHandler)
	mux.HandleFunc("/{$}", listHandler)

	log.Printf("running watchdogd on %s", listenAddr)
	if err := http.ListenAndServe(listenAddr, mux); err != nil {
		log.Fatal("watchdogd failed:", err)
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}

func ensure(err error) {
	if err != nil {
		panic(err)
	}
}
