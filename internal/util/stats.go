package util

import (
	"fmt"
	"strings"
	"sync"
)

// Stats tracks scanning statistics
type Stats struct {
	mu           sync.RWMutex
	GetRequests  int
	PostRequests int
	Requests     int
	Info         int
	Vulns        int
	URLs         int
}

// NewStats creates a new Stats instance with zeroed values
func NewStats() *Stats {
	return &Stats{}
}

// Reset resets all statistics to zero
func (s *Stats) Reset() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GetRequests = 0
	s.PostRequests = 0
	s.Requests = 0
	s.Info = 0
	s.Vulns = 0
	s.URLs = 0
}

// IncrementGetRequests safely increments GET request counter
func (s *Stats) IncrementGetRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.GetRequests++
}

// IncrementPostRequests safely increments POST request counter
func (s *Stats) IncrementPostRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.PostRequests++
}

// IncrementRequests safely increments generic request counter
func (s *Stats) IncrementRequests() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Requests++
}

// IncrementVulns safely increments vulnerability counter
func (s *Stats) IncrementVulns() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Vulns++
}

// IncrementURLs safely increments URL counter
func (s *Stats) IncrementURLs() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.URLs++
}

// IncrementInfo safely increments info counter
func (s *Stats) IncrementInfo() {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Info++
}

// TotalRequests returns the sum of all requests
func (s *Stats) TotalRequests() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.GetRequests + s.PostRequests + s.Requests
}

// GetVulns returns the vulnerability count
func (s *Stats) GetVulns() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.Vulns
}

// GetURLs returns the URL count
func (s *Stats) GetURLs() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.URLs
}

// GetTotalRequests returns total request count
func (s *Stats) GetTotalRequests() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.GetRequests + s.PostRequests + s.Requests
}

// GetGetRequestCount returns GET request count
func (s *Stats) GetGetRequestCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.GetRequests
}

// GetPostRequestCount returns POST request count
func (s *Stats) GetPostRequestCount() int {
	s.mu.RLock()
	defer s.mu.RUnlock()
	return s.PostRequests
}

// Print prints the final statistics
func (s *Stats) Print() {
	s.mu.RLock()
	defer s.mu.RUnlock()

	fmt.Println()
	fmt.Println(strings.Repeat("-", 40))
	fmt.Println("LFImap finished with execution.")
	fmt.Printf("Parameters tested: %d\n", s.URLs)
	fmt.Printf("Requests sent: %d\n", s.GetRequests+s.PostRequests+s.Requests)
	fmt.Printf("Vulnerabilities found: %d\n", s.Vulns)
}
