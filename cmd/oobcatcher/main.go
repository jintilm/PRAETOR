// oobcatcher runs a one-shot HTTP callback probe without modifying the server.
// Example: go run ./cmd/oobcatcher -task task-123 -ttl 30s
package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"time"

	"github.com/jintilm/praetor/internal/oob"
)

func main() {
	listen := flag.String("listen", "127.0.0.1:0", "HTTP bind address")
	publicURL := flag.String("public-url", "", "reachable HTTP(S) origin; defaults to listener address")
	task := flag.String("task", "", "task ID for this token")
	ttl := flag.Duration("ttl", 30*time.Second, "callback wait window")
	flag.Parse()
	if *task == "" || *ttl <= 0 {
		log.Fatal("-task and positive -ttl are required")
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		log.Fatal(err)
	}
	defer ln.Close()
	origin := *publicURL
	if origin == "" {
		origin = "http://" + ln.Addr().String()
	}
	catcher, err := oob.New(origin)
	if err != nil {
		log.Fatal(err)
	}
	probe, err := catcher.Issue(*task, *ttl)
	if err != nil {
		log.Fatal(err)
	}
	srv := &http.Server{Handler: catcher.Handler(), ReadHeaderTimeout: 5 * time.Second}
	go func() {
		if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
			log.Printf("HTTP listener: %v", err)
		}
	}()
	encoder := json.NewEncoder(os.Stdout)
	if err := encoder.Encode(probe); err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	evidence, err := catcher.Wait(ctx, probe.Token)
	if err != nil {
		log.Printf("wait ended: %v", err)
	}
	if err := encoder.Encode(evidence); err != nil {
		log.Fatal(err)
	}
	shutdown, done := context.WithTimeout(context.Background(), 3*time.Second)
	defer done()
	if err := srv.Shutdown(shutdown); err != nil {
		fmt.Fprintln(os.Stderr, err)
	}
}
