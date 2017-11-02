// Copyright (c) 2012-2016 Eli Janssen
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package camo

import (
	"regexp"
)

var acceptedContentTypes = []string{
	"application/font-woff",
	"application/vnd.ms-fontobject",
	"application/x-font",
	"font/",
	"image/",
	"text/css",
}

var defaultAcceptHeaders = "image/*, font/*, text/*, application/*"

// ValidReqHeaders are http request headers that are acceptable to pass from
// the client to the remote server. Only those present and true, are forwarded.
// Empty implies no filtering.
var ValidReqHeaders = map[string]bool{
	"Accept":         true,
	"Accept-Charset": true,
	// images (aside from xml/svg), don't generally benefit (generally) from
	// compression
	"Accept-Encoding":   false,
	"Accept-Language":   true,
	"Cache-Control":     true,
	"If-None-Match":     true,
	"If-Modified-Since": true,
	"X-Forwarded-For":   true,
}

// ValidRespHeaders are http response headers that are acceptable to pass from
// the remote server to the client. Only those present and true, are forwarded.
// Empty implies no filtering.
var ValidRespHeaders = map[string]bool{
	// Do not offer to accept range requests
	"Accept-Ranges":    false,
	"Cache-Control":    true,
	"Content-Encoding": true,
	"Content-Type":     true,
	"Etag":             true,
	"Expires":          true,
	"Last-Modified":    true,
	// override in response with either nothing, or ServerNameVer
	"Server":            false,
	"Transfer-Encoding": true,
}

// networks to reject
var rejectIPv4Networks = mustParseNetmasks(
	[]string{
		// ipv4 loopback
		"127.0.0.0/8",
		// ipv4 link local
		"169.254.0.0/16",
		// ipv4 rfc1918
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
	},
)

var rejectIPv6Networks = mustParseNetmasks(
	[]string{
		// ipv6 loopback
		"::1/128",
		// ipv6 link local
		"fe80::/10",
		// old ipv6 site local
		"fec0::/10",
		// ipv6 ULA
		"fc00::/7",
		// ipv4 mapped onto ipv6
		"::ffff:0:0/96",
	},
)

// match for localhost
var localhostRegex = regexp.MustCompile(`^localhost\.?(localdomain)?\.?$`)
