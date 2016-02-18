// Copyright (c) 2012-2016 Eli Janssen
// Use of this source code is governed by an MIT-style
// license that can be found in the LICENSE file.

package camo_test

import (
	"log"
	"sync"

	"go-camo/camo"
)

type ProxyStats struct {
	sync.RWMutex
	clients uint64
	bytes   uint64
}

func (ps *ProxyStats) AddServed() {
	ps.Lock()
	ps.clients++
	ps.Unlock()
}

func (ps *ProxyStats) AddBytes(bc int64) {
	if bc <= 0 {
		return
	}
	ps.Lock()
	ps.bytes += uint64(bc)
	ps.Unlock()
}

func (ps *ProxyStats) GetStats() (uint64, uint64) {
	ps.RLock()
	defer ps.RUnlock()
	return ps.bytes, ps.clients
}

func ExampleProxyMetrics() {
	config := camo.Config{}
	proxy, err := camo.New(config)
	if err != nil {
		log.Fatal("Error: ", err)
	}
	ps := &ProxyStats{}
	proxy.SetMetricsCollector(ps)
}
