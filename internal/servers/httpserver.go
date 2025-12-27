package servers

import (
	"context"
	"fmt"
	"net/http"
	"sync"
	"time"

	"github.com/hansmach1ne/lfimap/internal/util"
)

// HTTPServer serves RFI test payloads
type HTTPServer struct {
	server    *http.Server
	port      int
	colors    *util.Colors
	hitsMutex sync.RWMutex
	hits      map[string]bool
	running   bool
	mu        sync.Mutex
}

// NewHTTPServer creates a new HTTP server for RFI testing
func NewHTTPServer(port int, colors *util.Colors) *HTTPServer {
	return &HTTPServer{
		port:   port,
		colors: colors,
		hits:   make(map[string]bool),
	}
}

// Start starts the HTTP server
func (s *HTTPServer) Start() error {
	s.mu.Lock()
	if s.running {
		s.mu.Unlock()
		return nil
	}
	s.running = true
	s.mu.Unlock()

	mux := http.NewServeMux()

	// RFI test endpoint - serves a marker that can be detected
	mux.HandleFunc("/ysvznc", s.handleRFI)
	mux.HandleFunc("/ysvznc.php", s.handleRFI)
	mux.HandleFunc("/ysvznc.jsp", s.handleRFI)
	mux.HandleFunc("/ysvznc.html", s.handleRFI)
	mux.HandleFunc("/ysvznc.gif", s.handleRFI)
	mux.HandleFunc("/ysvznc.png", s.handleRFI)

	// Catch-all handler for other requests
	mux.HandleFunc("/", s.handleDefault)

	s.server = &http.Server{
		Addr:         fmt.Sprintf(":%d", s.port),
		Handler:      mux,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 10 * time.Second,
	}

	go func() {
		if err := s.server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			fmt.Printf("%s HTTP server error: %v\n", s.colors.Red("[-]"), err)
		}
	}()

	fmt.Printf("%s Started HTTP server on port %d for RFI testing\n", s.colors.LightBlue("[i]"), s.port)
	return nil
}

// handleRFI handles RFI test requests
func (s *HTTPServer) handleRFI(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr

	s.hitsMutex.Lock()
	if !s.hits[clientIP] {
		s.hits[clientIP] = true
		fmt.Printf("%s RFI callback received from %s - Path: %s\n",
			s.colors.Green("[+]"), clientIP, r.URL.Path)
	}
	s.hitsMutex.Unlock()

	// Return the RFI marker content
	w.Header().Set("Content-Type", "text/plain")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("ysvznc13371337"))
}

// handleDefault handles any other requests
func (s *HTTPServer) handleDefault(w http.ResponseWriter, r *http.Request) {
	clientIP := r.RemoteAddr
	fmt.Printf("%s HTTP request from %s - Path: %s\n",
		s.colors.LightBlue("[i]"), clientIP, r.URL.Path)

	w.WriteHeader(http.StatusNotFound)
	w.Write([]byte("Not Found"))
}

// Stop stops the HTTP server
func (s *HTTPServer) Stop() error {
	s.mu.Lock()
	defer s.mu.Unlock()

	if !s.running || s.server == nil {
		return nil
	}

	s.running = false
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	return s.server.Shutdown(ctx)
}

// HasHit checks if an IP has hit the server
func (s *HTTPServer) HasHit(ip string) bool {
	s.hitsMutex.RLock()
	defer s.hitsMutex.RUnlock()
	return s.hits[ip]
}

// GetHits returns all IPs that have hit the server
func (s *HTTPServer) GetHits() []string {
	s.hitsMutex.RLock()
	defer s.hitsMutex.RUnlock()

	ips := make([]string, 0, len(s.hits))
	for ip := range s.hits {
		ips = append(ips, ip)
	}
	return ips
}
