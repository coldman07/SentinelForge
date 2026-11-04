// update-verify signs release manifests and verifies signatures and artifact digests.
// It deliberately does not install or execute an artifact.
package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strings"
)

type signedFields struct {
	Version string `json:"version"`
	SHA256  string `json:"sha256"`
}

type manifest struct {
	Version   string `json:"version"`
	SHA256    string `json:"sha256"`
	Signature string `json:"signature"`
}

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 3 && args[0] == "keygen" {
		publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			return err
		}
		if err := writeNew(args[1], []byte(base64.StdEncoding.EncodeToString(privateKey)+"\n"), 0600); err != nil {
			return err
		}
		return writeNew(args[2], []byte(base64.StdEncoding.EncodeToString(publicKey)+"\n"), 0644)
	}
	if len(args) < 4 {
		return errors.New("usage: update-verify verify <artifact> <public-key-base64-file> <manifest.json> | sign <artifact> <version> <private-key-base64-file> <manifest.json>")
	}
	action, artifactPath := args[0], args[1]
	artifact, err := os.ReadFile(artifactPath)
	if err != nil {
		return err
	}
	digest := sha256.Sum256(artifact)
	fields := signedFields{Version: "", SHA256: hex.EncodeToString(digest[:])}
	switch action {
	case "sign":
		if len(args) != 5 {
			return errors.New("usage: update-verify sign <artifact> <version> <private-key-base64-file> <manifest.json>")
		}
		fields.Version = args[2]
		keyData, err := os.ReadFile(args[3])
		if err != nil {
			return err
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyData)))
		if err != nil {
			return fmt.Errorf("decode base64 key: %w", err)
		}
		if len(key) != ed25519.PrivateKeySize {
			return errors.New("private key must be a base64 encoded Ed25519 private key")
		}
		payload, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		m := manifest{Version: fields.Version, SHA256: fields.SHA256, Signature: base64.StdEncoding.EncodeToString(ed25519.Sign(ed25519.PrivateKey(key), payload))}
		encoded, err := json.MarshalIndent(m, "", "  ")
		if err != nil {
			return err
		}
		return os.WriteFile(args[4], append(encoded, '\n'), 0600)
	case "verify":
		if len(args) != 4 {
			return errors.New("usage: update-verify verify <artifact> <public-key-base64-file> <manifest.json>")
		}
		keyData, err := os.ReadFile(args[2])
		if err != nil {
			return err
		}
		key, err := base64.StdEncoding.DecodeString(strings.TrimSpace(string(keyData)))
		if err != nil {
			return fmt.Errorf("decode base64 key: %w", err)
		}
		if len(key) != ed25519.PublicKeySize {
			return errors.New("public key must be a base64 encoded Ed25519 public key")
		}
		encoded, err := os.ReadFile(args[3])
		if err != nil {
			return err
		}
		var m manifest
		if err := json.Unmarshal(encoded, &m); err != nil {
			return err
		}
		if m.SHA256 != fields.SHA256 {
			return errors.New("artifact SHA-256 does not match signed manifest")
		}
		fields.Version = m.Version
		signature, err := base64.StdEncoding.DecodeString(m.Signature)
		if err != nil {
			return err
		}
		payload, err := json.Marshal(fields)
		if err != nil {
			return err
		}
		if !ed25519.Verify(ed25519.PublicKey(key), payload, signature) {
			return errors.New("manifest signature is invalid")
		}
		fmt.Printf("verified %s (%s)\n", m.Version, m.SHA256)
		return nil
	default:
		return errors.New("action must be sign or verify")
	}
}

func writeNew(path string, data []byte, mode os.FileMode) error {
	file, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, mode)
	if err != nil {
		return err
	}
	if _, err := file.Write(data); err != nil {
		_ = file.Close()
		return err
	}
	return file.Close()
}
