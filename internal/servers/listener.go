package servers

import (
	"bufio"
	"fmt"
	"io"
	"net"
	"os"
	"sync"
	"time"

	"github.com/hansmach1ne/lfimap/internal/util"
)

// Listener handles reverse shell connections
type Listener struct {
	listener   net.Listener
	port       int
	colors     *util.Colors
	running    bool
	mu         sync.Mutex
	activeConn net.Conn
}

// NewListener creates a new reverse shell listener
func NewListener(port int, colors *util.Colors) *Listener {
	return &Listener{
		port:   port,
		colors: colors,
	}
}

// Start starts the listener
func (l *Listener) Start() error {
	l.mu.Lock()
	if l.running {
		l.mu.Unlock()
		return nil
	}

	listener, err := net.Listen("tcp", fmt.Sprintf(":%d", l.port))
	if err != nil {
		l.mu.Unlock()
		return fmt.Errorf("failed to start listener: %w", err)
	}

	l.listener = listener
	l.running = true
	l.mu.Unlock()

	fmt.Printf("%s Listening for reverse shell on port %d...\n", l.colors.LightBlue("[i]"), l.port)

	go l.acceptConnections()

	return nil
}

// acceptConnections accepts incoming connections
func (l *Listener) acceptConnections() {
	for {
		l.mu.Lock()
		if !l.running {
			l.mu.Unlock()
			return
		}
		listener := l.listener
		l.mu.Unlock()

		conn, err := listener.Accept()
		if err != nil {
			l.mu.Lock()
			if l.running {
				fmt.Printf("%s Accept error: %v\n", l.colors.Red("[-]"), err)
			}
			l.mu.Unlock()
			continue
		}

		l.handleConnection(conn)
	}
}

// handleConnection handles a single reverse shell connection
func (l *Listener) handleConnection(conn net.Conn) {
	remoteAddr := conn.RemoteAddr().String()
	fmt.Printf("\n%s Received connection from %s\n", l.colors.Green("[+]"), remoteAddr)
	fmt.Printf("%s Shell session started. Type 'exit' to close connection.\n", l.colors.LightBlue("[i]"))

	l.mu.Lock()
	l.activeConn = conn
	l.mu.Unlock()

	defer func() {
		conn.Close()
		l.mu.Lock()
		l.activeConn = nil
		l.mu.Unlock()
		fmt.Printf("\n%s Connection from %s closed\n", l.colors.Yellow("[!]"), remoteAddr)
	}()

	// Create channels for bidirectional communication
	done := make(chan struct{})

	// Read from connection and write to stdout
	go func() {
		defer close(done)
		buf := make([]byte, 4096)
		for {
			conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
			n, err := conn.Read(buf)
			if err != nil {
				if netErr, ok := err.(net.Error); ok && netErr.Timeout() {
					continue
				}
				if err != io.EOF {
					return
				}
				return
			}
			if n > 0 {
				os.Stdout.Write(buf[:n])
			}
		}
	}()

	// Read from stdin and write to connection
	go func() {
		scanner := bufio.NewScanner(os.Stdin)
		for scanner.Scan() {
			text := scanner.Text()
			if text == "exit" {
				conn.Close()
				return
			}
			_, err := conn.Write([]byte(text + "\n"))
			if err != nil {
				return
			}
		}
	}()

	<-done
}

// Stop stops the listener
func (l *Listener) Stop() error {
	l.mu.Lock()
	defer l.mu.Unlock()

	if !l.running {
		return nil
	}

	l.running = false

	if l.activeConn != nil {
		l.activeConn.Close()
	}

	if l.listener != nil {
		return l.listener.Close()
	}

	return nil
}

// IsRunning returns true if the listener is running
func (l *Listener) IsRunning() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.running
}

// StartListener is a convenience function for starting a listener (used by exploit module)
func StartListener(port int, colors *util.Colors) {
	listener := NewListener(port, colors)
	if err := listener.Start(); err != nil {
		fmt.Printf("%s Failed to start listener: %v\n", colors.Red("[-]"), err)
		return
	}

	// Keep running until stopped
	select {}
}
