package http

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"net/http"
	"strings"
)

// Parser handles parsing of HTTP data from SSL traffic
type Parser struct{}

// NewParser creates a new HTTP parser
func NewParser() *Parser {
	return &Parser{}
}

// ParseData attempts to extract HTTP data from raw SSL data
// Returns the body data and whether it was successfully parsed
func (p *Parser) ParseData(data []byte) ([]byte, error) {
	// Try to parse as HTTP request first
	if body, err := p.parseHTTPRequest(data); err == nil && body != nil {
		return body, nil
	}

	// Try to parse as HTTP response
	if body, err := p.parseHTTPResponse(data); err == nil && body != nil {
		return body, nil
	}

	// If it's not HTTP, return nil (not an error, just not HTTP)
	return nil, nil
}

// parseHTTPRequest tries to parse data as an HTTP request
func (p *Parser) parseHTTPRequest(data []byte) ([]byte, error) {
	reader := bufio.NewReader(bytes.NewReader(data))

	// Check if this looks like an HTTP request
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	// HTTP requests start with METHOD PATH HTTP/VERSION
	parts := strings.Fields(firstLine)
	if len(parts) < 3 || !strings.HasPrefix(parts[2], "HTTP/") {
		return nil, fmt.Errorf("not an HTTP request")
	}

	// Parse the request
	req, err := http.ReadRequest(bufio.NewReader(bytes.NewReader(data)))
	if err != nil {
		return nil, err
	}
	defer req.Body.Close()

	// Read the body
	body, err := io.ReadAll(req.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}

// parseHTTPResponse tries to parse data as an HTTP response
func (p *Parser) parseHTTPResponse(data []byte) ([]byte, error) {
	reader := bufio.NewReader(bytes.NewReader(data))

	// Check if this looks like an HTTP response
	firstLine, err := reader.ReadString('\n')
	if err != nil {
		return nil, err
	}

	// HTTP responses start with HTTP/VERSION STATUS_CODE
	if !strings.HasPrefix(firstLine, "HTTP/") {
		return nil, fmt.Errorf("not an HTTP response")
	}

	// Parse the response
	resp, err := http.ReadResponse(bufio.NewReader(bytes.NewReader(data)), nil)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	// Read the body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	return body, nil
}
