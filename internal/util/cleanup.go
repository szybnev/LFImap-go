package util

import (
	"os"
	"path/filepath"
)

// Cleanup removes temporary files created during exploitation
func Cleanup(webDir string, stats *Stats) {
	// Remove temporary reverse shell files
	tempFiles := []string{
		"reverse_shell_lin_tmp.php",
		"reverse_shell_win_tmp.php",
	}

	for _, f := range tempFiles {
		path := filepath.Join(webDir, f)
		os.Remove(path) // Ignore errors, file may not exist
	}

	// Print statistics
	if stats != nil {
		stats.Print()
	}
}

// CleanupAndExit performs cleanup and exits the program
func CleanupAndExit(webDir string, stats *Stats, exitCode int) {
	Cleanup(webDir, stats)
	os.Exit(exitCode)
}
