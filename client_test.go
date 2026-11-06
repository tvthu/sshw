package sshw

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"net"
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
)

func TestSetupAgentAuthUsesEnv(t *testing.T) {
	sock := filepath.Join(t.TempDir(), "agent.sock")
	ln, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	go func() {
		conn, err := ln.Accept()
		if err == nil {
			_ = agent.ServeAgent(agent.NewKeyring(), conn)
			conn.Close()
		}
	}()

	t.Setenv("SSH_AUTH_SOCK", sock)
	auth, cleanup, err := setupAgentAuth(&Node{})
	if err != nil || auth == nil || cleanup == nil {
		t.Fatalf("expected agent auth from SSH_AUTH_SOCK, got auth=%v err=%v", auth, err)
	}
	cleanup()
}

func TestSetupDefaultKeyAuthLoadsEd25519(t *testing.T) {
	home := t.TempDir()
	sshDir := filepath.Join(home, ".ssh")
	if err := os.MkdirAll(sshDir, 0700); err != nil {
		t.Fatal(err)
	}
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	block, err := ssh.MarshalPrivateKey(priv, "")
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(sshDir, "id_ed25519"), pem.EncodeToMemory(block), 0600); err != nil {
		t.Fatal(err)
	}

	t.Setenv("HOME", home)
	auth, _, err := setupDefaultKeyAuth(&Node{})
	if err != nil || auth == nil {
		t.Fatalf("expected default key auth to load id_ed25519, got auth=%v err=%v", auth, err)
	}
}
