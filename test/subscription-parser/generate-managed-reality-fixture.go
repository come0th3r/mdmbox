// Command generate-managed-reality-fixture creates disposable localhost-only
// inputs for the combined managed refresh/runtime fixture. Never commit its
// output: the generated REALITY private key and client credentials are secrets,
// even though they are synthetic and short-lived.
package main

import (
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
)

func freeLoopbackPort() int {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		panic("could not reserve a synthetic loopback port")
	}
	defer listener.Close()
	return listener.Addr().(*net.TCPAddr).Port
}

func writeJSON(path string, value any) {
	data, err := json.MarshalIndent(value, "", "  ")
	if err != nil {
		panic("could not encode synthetic server config")
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		panic("could not write synthetic server config")
	}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: generate-managed-reality-fixture <existing-temp-directory>")
		os.Exit(2)
	}
	root := os.Args[1]
	info, err := os.Stat(root)
	if err != nil || !info.IsDir() {
		fmt.Fprintln(os.Stderr, "fixture directory must already exist")
		os.Exit(2)
	}

	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		panic("could not generate synthetic REALITY key")
	}
	uuidBytes := make([]byte, 16)
	if _, err := rand.Read(uuidBytes); err != nil {
		panic("could not generate synthetic client UUID")
	}
	uuidBytes[6] = (uuidBytes[6] & 0x0f) | 0x40
	uuidBytes[8] = (uuidBytes[8] & 0x3f) | 0x80
	uuid := fmt.Sprintf("%x-%x-%x-%x-%x",
		uuidBytes[:4], uuidBytes[4:6], uuidBytes[6:8], uuidBytes[8:10], uuidBytes[10:])
	shortIDBytes := make([]byte, 8)
	if _, err := rand.Read(shortIDBytes); err != nil {
		panic("could not generate synthetic REALITY short ID")
	}
	shortID := hex.EncodeToString(shortIDBytes)
	serverPort, camouflagePort := freeLoopbackPort(), freeLoopbackPort()
	for camouflagePort == serverPort {
		camouflagePort = freeLoopbackPort()
	}

	serverConfig := map[string]any{
		"log": map[string]any{"level": "warning"},
		"inbounds": []any{map[string]any{
			"type": "vless", "tag": "synthetic-reality", "listen": "127.0.0.1", "listen_port": serverPort,
			"users": []any{map[string]any{"uuid": uuid, "flow": "xtls-rprx-vision"}},
			"tls": map[string]any{
				"enabled": true, "server_name": "reality.test",
				"reality": map[string]any{
					"enabled": true, "private_key": base64.RawURLEncoding.EncodeToString(privateKey.Bytes()),
					"short_id": []string{shortID},
					"handshake": map[string]any{"server": "127.0.0.1", "server_port": camouflagePort},
				},
			},
		}},
		"outbounds": []any{map[string]any{"type": "direct", "tag": "direct"}},
		"route":    map[string]any{"final": "direct"},
	}
	writeJSON(filepath.Join(root, "reality-server.json"), serverConfig)

	profile := fmt.Sprintf("proxies:\n"+
		"  - name: synthetic-reality\n"+
		"    type: vless\n"+
		"    server: 127.0.0.1\n"+
		"    port: %d\n"+
		"    uuid: %s\n"+
		"    flow: xtls-rprx-vision\n"+
		"    tls: true\n"+
		"    network: tcp\n"+
		"    servername: reality.test\n"+
		"    client-fingerprint: chrome\n"+
		"    reality-opts:\n"+
		"      public-key: %s\n"+
		"      short-id: %s\n"+
		"proxy-groups:\n"+
		"  - name: synthetic-select\n"+
		"    type: select\n"+
		"    proxies: [synthetic-reality]\n"+
		"rules:\n"+
		"  - MATCH,synthetic-select\n"+
		"dns:\n"+
		"  enable: false\n"+
		"  nameserver: [127.0.0.1]\n",
		serverPort, uuid, base64.RawURLEncoding.EncodeToString(privateKey.PublicKey().Bytes()), shortID)
	if err := os.WriteFile(filepath.Join(root, "managed-reality.yaml"), []byte(profile), 0600); err != nil {
		panic("could not write synthetic managed profile")
	}
	fmt.Println("SYNTHETIC_MANAGED_REALITY_PROFILE_CREATED loopback_only=true")
}
