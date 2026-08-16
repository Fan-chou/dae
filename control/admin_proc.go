/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bufio"
	"bytes"
	"os"
	"strconv"
)

func readSelfRSSAndFDs() (rssBytes uint64, fdCount int) {
	data, err := os.ReadFile("/proc/self/status")
	if err == nil {
		scanner := bufio.NewScanner(bytes.NewReader(data))
		for scanner.Scan() {
			line := scanner.Bytes()
			if !bytes.HasPrefix(line, []byte("VmRSS:")) {
				continue
			}
			fields := bytes.Fields(line)
			if len(fields) < 2 {
				break
			}
			kb, parseErr := strconv.ParseUint(string(fields[1]), 10, 64)
			if parseErr == nil {
				rssBytes = kb * 1024
			}
			break
		}
	}
	if entries, dirErr := os.ReadDir("/proc/self/fd"); dirErr == nil {
		fdCount = len(entries)
	}
	return rssBytes, fdCount
}
