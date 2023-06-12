package main

import (
	"crypto/tls"
	"errors"
	"fmt"
	"golang.org/x/net/http2"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
)

// https://stackoverflow.com/a/40883377

type keypairReloader struct {
	certMu   sync.RWMutex
	cert     *tls.Certificate
	certPath string
	keyPath  string
}

func NewKeypairReloader(certPath, keyPath string) (*keypairReloader, error) {
	result := &keypairReloader{
		certPath: certPath,
		keyPath:  keyPath,
	}
	cert, err := tls.LoadX509KeyPair(certPath, keyPath)
	if err != nil {
		return nil, err
	}
	result.cert = &cert
	go func() {
		c := make(chan os.Signal, 1)
		signal.Notify(c, syscall.SIGHUP)
		for range c {
			log.Printf("Received SIGHUP, reloading TLS certificate and key from %q and %q", certPath, keyPath)
			if err := result.maybeReload(); err != nil {
				log.Printf("Keeping old TLS certificate because the new one could not be loaded: %v", err)
			}
		}
	}()
	return result, nil
}

func (kpr *keypairReloader) maybeReload() error {
	newCert, err := tls.LoadX509KeyPair(kpr.certPath, kpr.keyPath)
	if err != nil {
		return err
	}
	kpr.certMu.Lock()
	defer kpr.certMu.Unlock()
	kpr.cert = &newCert
	return nil
}

func (kpr *keypairReloader) GetCertificateFunc() func(*tls.ClientHelloInfo) (*tls.Certificate, error) {
	return func(clientHello *tls.ClientHelloInfo) (*tls.Certificate, error) {
		kpr.certMu.RLock()
		defer kpr.certMu.RUnlock()
		return kpr.cert, nil
	}
}

func installAdHocIpa(w http.ResponseWriter, r *http.Request) {
	path := r.URL.Path
	if strings.HasSuffix(path, ".plist") {
		splitPath := strings.Split(path, "/")
		ipaPath := "https://" + strings.Join(splitPath[2:len(splitPath)-4], "/")
		bundleIdentifier := splitPath[len(splitPath) - 4]
		version := splitPath[len(splitPath) - 3]
		name := splitPath[len(splitPath) - 2]
		bodyFmt := `<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "https://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
    <dict>
        <key>items</key>
        <array>
            <dict>
                <key>assets</key>
                <array>
                    <dict>
                        <key>kind</key>
                        <string>software-package</string>
                        <key>url</key>
                        <string>%s</string>
                    </dict>
                </array>
                <key>metadata</key>
                <dict>
                    <key>bundle-identifier</key>
                    <string>%s</string>
                    <key>bundle-version</key>
                    <string>%s</string>
                    <key>kind</key>
                    <string>software</string>
                    <key>title</key>
                    <string>%s</string>
                </dict>
            </dict>
        </array>
    </dict>
</plist>
`
		body := fmt.Sprintf(bodyFmt, ipaPath, bundleIdentifier, version, name)
		w.Header().Add("content-type", "application/xml")
		_, _ = w.Write([]byte(body))
	} else if strings.HasSuffix(path, "/install") {
		plistUrl := r.URL.Query()["plistUrl"][0]
		redirectUrl := "itms-services://?action=download-manifest&url=" + plistUrl
		http.Redirect(w, r, redirectUrl, 302)
	} else {
		_, _ = w.Write([]byte("unknown"))
	}
}

// Copied from src/net/http/server.go
type tcpKeepAliveListener struct {
	*net.TCPListener
}

func (ln tcpKeepAliveListener) Accept() (c net.Conn, err error) {
	tc, err := ln.AcceptTCP()
	if err != nil {
		return
	}
	err = tc.SetKeepAlive(true)
	if err != nil {
		return nil, err
	}
	err = tc.SetKeepAlivePeriod(3 * time.Minute)
	if err != nil {
		return nil, err
	}
	return tc, nil
}

func main() {
	if len(os.Args) != 4 {
		fmt.Println("Command argument: [PORT] [CERT FILE PATH] [KEY FILE PATH]")
		panic(errors.New("argument count should be 3"))
	} else {
		baseDomain := "example.com"
		port := os.Args[1]
		ipaUrl := "https://example.com/app.ipa"
		packageName := "com.example.app"
		buildNumber := "1234"
		appName := "TestApp"

		certPath := os.Args[2]
		keyPath := os.Args[3]

		http.HandleFunc("/", installAdHocIpa)
		fmt.Println("Start listening on port " + port)
		fmt.Println()
		fmt.Println("Cert file: " + certPath)
		fmt.Println("Key file: " + keyPath)
		fmt.Println()
		fmt.Println("Access URL format:")
		fmt.Println("    https://" + baseDomain + ":" + port + "/install?plistUrl=[IPA URL]/[PACKAGE NAME]/[BUILD NUMBER]/[APP NAME]/dummy.plist")
		fmt.Println("Access URL example:")
		fmt.Println("    https://" + baseDomain + ":" + port + "/install?plistUrl=" + ipaUrl + "/" + packageName + "/" + buildNumber + "/" + appName + "/dummy.plist")

		listen := ":" + os.Args[1]

		server := &http.Server{Addr: listen}
		if err := http2.ConfigureServer(server, nil); err != nil {
			panic(err)
		}

		server.TLSConfig.Certificates = make([]tls.Certificate, 1)
		cert, err := tls.LoadX509KeyPair(certPath, keyPath)
		if err != nil {
			panic(err)
		}

		server.TLSConfig.Certificates[0] = cert

		kpr, err := NewKeypairReloader(certPath, keyPath)
		if err != nil {
			panic(err)
		}
		server.TLSConfig.GetCertificate = kpr.GetCertificateFunc()

		ln, err := net.Listen("tcp", listen)
		if err != nil {
			panic(err)
		}

		tlsListener := tls.NewListener(tcpKeepAliveListener{ln.(*net.TCPListener)}, server.TLSConfig)
		if err := server.Serve(tlsListener); err != nil {
			panic(err)
		}
	}
}
