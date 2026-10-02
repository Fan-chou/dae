/*
 * SPDX-License-Identifier: AGPL-3.0-only
 * Copyright (c) 2022-2026, daeuniverse Organization <dae@v2raya.org>
 */

package control

import (
	"bytes"
	"context"
	"testing"
)

type qualityTestConn struct {
	blockingMockConn
	input      *bytes.Reader
	output     bytes.Buffer
	halfClosed bool
}

func (c *qualityTestConn) Read(p []byte) (int, error)  { return c.input.Read(p) }
func (c *qualityTestConn) Write(p []byte) (int, error) { return c.output.Write(p) }
func (c *qualityTestConn) CloseWrite() error           { c.halfClosed = true; return nil }
func TestQualityRelayPreservesPayloadAccountingAndHalfClose(t *testing.T) {
	for _, downstream := range []bool{false, true} {
		payload := bytes.Repeat([]byte("payload"), 8192)
		src := &qualityTestConn{input: bytes.NewReader(payload)}
		dst := &qualityTestConn{}
		engine := qualityRelayCopyEngine{}
		if downstream {
			engine.ingress = dst
		} else {
			engine.ingress = src
		}
		var recorded int64
		n, err := engine.Copy(context.Background(), dst, src, func(n int64) { recorded += n }, nil)
		if err != nil || n != int64(len(payload)) || recorded != n || !bytes.Equal(dst.output.Bytes(), payload) {
			t.Fatalf("copy downstream=%v n=%d recorded=%d err=%v", downstream, n, recorded, err)
		}
		wrapper := &qualityWriteConn{Conn: dst}
		if err := wrapper.CloseWrite(); err != nil || !dst.halfClosed {
			t.Fatal("half close lost")
		}
	}
}
