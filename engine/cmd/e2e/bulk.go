package main

import (
	"crypto/sha256"
	"fmt"
	"io"
	"net"
	"strconv"
	"time"
)

const (
	bulkDown = 512 << 10
	bulkUp   = 256 << 10
)

func bulkBlob(n int) []byte {
	b := make([]byte, n)
	for i := range b {
		b[i] = byte(i*31 + i>>7 + 7)
	}
	return b
}

func bulkServer(ln net.Listener, done chan<- int64) {
	conn, err := ln.Accept()
	if err != nil {
		done <- -1
		return
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(240 * time.Second))
	if _, err := conn.Write(bulkBlob(bulkDown)); err != nil {
		done <- -1
		return
	}
	buf := make([]byte, bulkUp)
	n, _ := io.ReadFull(conn, buf)
	done <- int64(n)
}
func checkBulk(listen string) error {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer ln.Close()
	_, portStr, _ := net.SplitHostPort(ln.Addr().String())
	port, _ := strconv.Atoi(portStr)
	done := make(chan int64, 1)
	go bulkServer(ln, done)

	conn, err := dial(listen)
	if err != nil {
		return err
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(240 * time.Second))
	if err := socksConnect(conn, "127.0.0.1", uint16(port)); err != nil {
		return fmt.Errorf("bulk connect: %w", err)
	}

	want := bulkBlob(bulkDown)
	got := make([]byte, 0, bulkDown)
	buf := make([]byte, 32<<10)
	for len(got) < bulkDown {
		n, err := conn.Read(buf)
		if n > 0 {
			got = append(got, buf[:n]...)
		}
		if err != nil {
			break
		}
	}
	if len(got) != bulkDown {
		return fmt.Errorf("download short: %d/%d bytes", len(got), bulkDown)
	}
	if sha256.Sum256(got) != sha256.Sum256(want) {
		return fmt.Errorf("download corrupted (%d bytes)", len(got))
	}
	up := bulkBlob(bulkUp)
	if _, err := conn.Write(up); err != nil {
		return fmt.Errorf("upload write: %w", err)
	}
	if got := <-done; got != bulkUp {
		return fmt.Errorf("upload short: server got %d/%d", got, bulkUp)
	}
	return nil
}
