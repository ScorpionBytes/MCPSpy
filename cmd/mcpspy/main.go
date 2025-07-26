package main

import (
	"context"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/sirupsen/logrus"
	"github.com/spf13/cobra"

	"github.com/alex-ilgayev/mcpspy/pkg/ebpf"
	"github.com/alex-ilgayev/mcpspy/pkg/http"
	"github.com/alex-ilgayev/mcpspy/pkg/mcp"
	"github.com/alex-ilgayev/mcpspy/pkg/output"
	"github.com/alex-ilgayev/mcpspy/pkg/version"

	mcpspydebug "github.com/alex-ilgayev/mcpspy/pkg/debug"
)

// Command line flags
var (
	showBuffers bool
	verbose     bool
	outputFile  string
	logLevel    string
)

func main() {
	rootCmd := &cobra.Command{
		Use:   "mcpspy",
		Short: "Monitor Model Context Protocol communication",
		Long: `MCPSpy is a CLI utility that uses eBPF to monitor MCP (Model Context Protocol) 
communication by tracking stdio operations and analyzing JSON-RPC 2.0 messages.`,
		Version:      fmt.Sprintf("%s (commit: %s, built: %s)", version.Version, version.Commit, version.Date),
		RunE:         run,
		SilenceUsage: true,
	}

	// Add flags
	rootCmd.Flags().BoolVarP(&showBuffers, "buffers", "b", false, "Show raw message buffers")
	rootCmd.Flags().BoolVarP(&verbose, "verbose", "v", false, "Enable verbose logging (debug level)")
	rootCmd.Flags().StringVarP(&outputFile, "output", "o", "", "Output file (JSONL format will be written to file)")
	rootCmd.Flags().StringVarP(&logLevel, "log-level", "l", "info", "Set log level (trace, debug, info, warn, error, fatal, panic)")

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func run(cmd *cobra.Command, args []string) error {
	// Set up logging
	// Handle verbose flag as shortcut for debug level
	if verbose {
		logLevel = "debug"
	}

	// Parse and set log level
	level, err := logrus.ParseLevel(logLevel)
	if err != nil {
		return fmt.Errorf("invalid log level '%s': %w", logLevel, err)
	}
	logrus.SetLevel(level)

	// Setup trace pipe to debug eBPF programs if debug or trace level
	if level >= logrus.DebugLevel {
		go mcpspydebug.PrintTracePipe(logrus.StandardLogger())
	}

	// Set up console display (always show console output)
	consoleDisplay := output.NewConsoleDisplay(os.Stdout, showBuffers)
	consoleDisplay.PrintHeader()

	// Set up file output if specified
	var fileDisplay output.OutputHandler

	if outputFile != "" {
		file, err := os.Create(outputFile)
		if err != nil {
			return fmt.Errorf("failed to create output file '%s': %w", outputFile, err)
		}
		fileDisplay = output.NewJSONLDisplay(file)
		defer func() {
			if err := file.Close(); err != nil {
				logrus.WithError(err).Error("Failed to close output file")
			}
		}()
	}

	// Create and load eBPF program
	loader, err := ebpf.New(level >= logrus.DebugLevel)
	if err != nil {
		return fmt.Errorf("failed to create eBPF loader: %w", err)
	}
	defer loader.Close()

	consoleDisplay.PrintInfo("Loading eBPF programs...")
	if err := loader.Load(); err != nil {
		return fmt.Errorf("failed to load eBPF programs: %w", err)
	}

	// Set up signal handling
	ctx, cancel := context.WithCancel(context.Background())
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-sigChan
		cancel()
	}()

	// Start event processing
	if err := loader.Start(ctx); err != nil {
		return fmt.Errorf("failed to start event processing: %w", err)
	}

	consoleDisplay.PrintInfo("Monitoring MCP communication... Press Ctrl+C to stop")
	consoleDisplay.PrintInfo("")

	// Create MCP parser and statistics
	parser := mcp.NewParser()
	httpParser := http.NewParser()
	stats := make(map[string]int)

	// Main event loop
	for {
		select {
		case <-ctx.Done():
			consoleDisplay.PrintStats(stats)
			return nil

		case event, ok := <-loader.Events():
			if !ok {
				// Channel closed, exit
				consoleDisplay.PrintStats(stats)
				return nil
			}

			// Handle different event types
			switch e := event.(type) {
			case *ebpf.DataEvent:
				buf := e.Buf[:e.BufSize]
				if len(buf) == 0 {
					continue
				}

				// Check if this is likely HTTP data (could be from SSL probes)
				var messages []*mcp.Message
				var err error

				// Try to parse as HTTP first (for SSL traffic)
				httpBody, httpErr := httpParser.ParseData(buf)
				if httpErr == nil && httpBody != nil {
					// This is HTTP data, parse the body for MCP messages
					messages, err = parser.ParseHTTPData(httpBody, e.EventType, e.PID, e.Comm())
				} else {
					// Not HTTP, parse as regular stdio data
					messages, err = parser.ParseData(buf, e.EventType, e.PID, e.Comm())
				}

				if err != nil {
					logrus.WithError(err).Debug("Failed to parse data")
					continue
				}

				// Update statistics
				for _, msg := range messages {
					if msg.Method != "" {
						stats[msg.Method]++
					}
				}

				// Display messages to console
				consoleDisplay.PrintMessages(messages)

				// Also write to file if specified
				if fileDisplay != nil {
					fileDisplay.PrintMessages(messages)
				}
			case *ebpf.LibraryEvent:
				// Handle library events - check if it's an SSL library
				logrus.WithFields(logrus.Fields{
					"pid":  e.PID,
					"comm": e.Comm(),
					"path": e.Path(),
				}).Trace("Library loaded")

				// Check if this is an SSL library we should hook
				if isSSLLibrary(e.Path()) {
					logrus.WithFields(logrus.Fields{
						"pid":  e.PID,
						"comm": e.Comm(),
						"path": e.Path(),
					}).Info("SSL library detected, attaching SSL probes")

					if err := loader.AttachSSLProbes(e.Path()); err != nil {
						logrus.WithError(err).WithField("path", e.Path()).Warn("Failed to attach SSL probes")
					} else {
						logrus.WithField("path", e.Path()).Info("SSL probes attached successfully")
					}
				}
			default:
				logrus.WithField("type", event.Type()).Warn("Unknown event type")
			}
		}
	}
}

// isSSLLibrary checks if the given path is an SSL library we should hook
func isSSLLibrary(path string) bool {
	// List of patterns that indicate SSL libraries
	sslPatterns := []string{
		"libssl.so",
		"libssl3.so",
		"libssl.so.3",
		"libssl.so.1",
		// Also check for executables with statically linked SSL
		"/node", // Node.js often has SSL statically linked
	}

	for _, pattern := range sslPatterns {
		if strings.Contains(path, pattern) {
			return true
		}
	}

	return false
}
