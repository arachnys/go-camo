package camoproxy

import (
	"fmt"
	"github.com/cactus/gologit"
	"regexp"
)

const (
	ServerName    = "go-camo"
	ServerVersion = "0.0.3"
)

// Server Name with version
var ServerNameVer = fmt.Sprintf("%s %s", ServerName, ServerVersion)

// Logger for handling logging.
var Logger = gologit.New(false)

// Headers that are acceptible to pass from the client to the remote
// server. Only those present and true, are forwarded. Empty implies
// no filtering.
var ValidReqHeaders = map[string]bool{
	"Accept":            true,
	"Accept-Charset":    true,
	"Accept-Encoding":   true,
	"Accept-Language":   true,
	"Cache-Control":     true,
	"If-None-Match":     true,
	"If-Modified-Since": true,
	"X-Forwarded-For":   true,
}

// Headers that are acceptible to pass from the remote server to the
// client. Only those present and true, are forwarded. Empty implies
// no filtering.
var ValidRespHeaders = map[string]bool{
	// Do not offer to accept range requests
	"Accept-Ranges":     false,
	"Cache-Control":     true,
	"Content-Encoding":  true,
	"Content-Type":      true,
	"Transfer-Encoding": true,
	"Expires":           true,
	"Last-Modified":     true,
	// override in response with either nothing, or ServerNameVer
	"Server":            false,
	}

// addr1918match is a regex for matching hosts to rfc1918 addresses
var addr1918match, _ = regexp.Compile(`^(127\.|10\.|169\\.254|192\.168|^172\.(?:(?:1[6-9])|(?:2[0-9])|(?:3[0-1])))`)