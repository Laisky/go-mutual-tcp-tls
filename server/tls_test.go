package main

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/Laisky/go-utils"
	"github.com/stretchr/testify/require"
)

// TestSetupTLSAuthenticatesClient exercises the actual server configuration against local TLS peers.
func TestSetupTLSAuthenticatesClient(t *testing.T) {
	for _, name := range []string{"valid mutual authentication", "missing client certificate", "untrusted client certificate"} {
		t.Run(name, func(t *testing.T) {
			ca := newTestCA(t, "trusted authority")
			serverCertificate := issueTestCertificate(t, ca, "fixture server", x509.ExtKeyUsageServerAuth, true)
			serverConfig := loadTestTLS(t, ca, serverCertificate)
			clientConfig := &tls.Config{RootCAs: testPool(t, ca)}
			if name != "missing client certificate" {
				clientCA := ca
				if name == "untrusted client certificate" {
					clientCA = newTestCA(t, "untrusted client authority")
				}
				certificate := issueTestCertificate(t, clientCA, "fixture client", x509.ExtKeyUsageClientAuth, true)
				// Force presentation even when the issuer is absent from the server's advertised CA list.
				clientConfig.GetClientCertificate = func(*tls.CertificateRequestInfo) (*tls.Certificate, error) {
					return &certificate, nil
				}
			}
			clientState, clientErr, serverResult := exchangeTestTLS(t, serverConfig, clientConfig)
			if name == "valid mutual authentication" {
				require.NoError(t, clientErr)
				require.NoError(t, serverResult.err)
				require.Equal(t, "ephemeral mutual TLS\n", serverResult.payload)
				require.True(t, clientState.HandshakeComplete)
				require.True(t, serverResult.state.HandshakeComplete)
				require.Len(t, clientState.VerifiedChains, 1)
				require.Len(t, serverResult.state.VerifiedChains, 1)
				require.Equal(t, "fixture server", clientState.PeerCertificates[0].Subject.CommonName)
				require.Equal(t, "fixture client", serverResult.state.PeerCertificates[0].Subject.CommonName)
				return
			}
			require.Error(t, serverResult.err)
			require.Error(t, clientErr)
			require.Empty(t, serverResult.payload)
			if name == "missing client certificate" {
				require.Contains(t, serverResult.err.Error(), "client didn't provide a certificate")
			} else {
				require.Contains(t, serverResult.err.Error(), "unknown authority")
			}
		})
	}
}

// testCA contains only ephemeral certificate material owned by a test.
type testCA struct {
	certificate *x509.Certificate
	key         *ecdsa.PrivateKey
	pem         []byte
}

// newTestCA creates a temporary ECDSA authority with a one-hour validity period.
func newTestCA(t *testing.T, name string) testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	require.NoError(t, err)
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		IsCA: true, BasicConstraintsValid: true,
		KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	require.NoError(t, err)
	certificate, err := x509.ParseCertificate(der)
	require.NoError(t, err)
	return testCA{certificate: certificate, key: key,
		pem: pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})}
}

// issueTestCertificate signs an ephemeral client or server leaf for loopback use.
func issueTestCertificate(t *testing.T, ca testCA, name string, usage x509.ExtKeyUsage, validHost bool) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 120))
	require.NoError(t, err)
	now := time.Now().UTC()
	template := &x509.Certificate{
		SerialNumber: serial, Subject: pkix.Name{CommonName: name},
		NotBefore: now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{usage},
	}
	if usage == x509.ExtKeyUsageServerAuth {
		if validHost {
			template.DNSNames = []string{"localhost"}
			template.IPAddresses = []net.IP{net.ParseIP("127.0.0.1")}
		} else {
			template.DNSNames = []string{"wrong-host.example.test"}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, ca.certificate, &key.PublicKey, ca.key)
	require.NoError(t, err)
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	require.NoError(t, err)
	certificate, err := tls.X509KeyPair(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}))
	require.NoError(t, err)
	return certificate
}

// testPool returns a trust pool containing exactly the generated authority.
func testPool(t *testing.T, ca testCA) *x509.CertPool {
	t.Helper()
	pool := x509.NewCertPool()
	require.True(t, pool.AppendCertsFromPEM(ca.pem))
	return pool
}

// loadTestTLS invokes the application's setupTLS using private temporary files.
func loadTestTLS(t *testing.T, ca testCA, certificate tls.Certificate) *tls.Config {
	t.Helper()
	directory := t.TempDir()
	certPath := filepath.Join(directory, "leaf.pem")
	keyPath := filepath.Join(directory, "key.pem")
	caPath := filepath.Join(directory, "ca.pem")
	key, err := x509.MarshalPKCS8PrivateKey(certificate.PrivateKey)
	require.NoError(t, err)
	require.NoError(t, os.WriteFile(certPath, pem.EncodeToMemory(
		&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Certificate[0]}), 0600))
	require.NoError(t, os.WriteFile(keyPath, pem.EncodeToMemory(
		&pem.Block{Type: "PRIVATE KEY", Bytes: key}), 0600))
	require.NoError(t, os.WriteFile(caPath, ca.pem, 0600))
	for name, value := range map[string]string{"crt": certPath, "crt-key": keyPath, "ca": caPath} {
		name, previous := name, utils.Settings.Get(name)
		utils.Settings.Set(name, value)
		t.Cleanup(func() { utils.Settings.Set(name, previous) })
	}
	return setupTLS()
}

// testPeerResult records handshake and plaintext results without testing from a goroutine.
type testPeerResult struct {
	state   tls.ConnectionState
	payload string
	err     error
}

// exchangeTestTLS performs a bounded loopback handshake and acknowledged data transfer.
func exchangeTestTLS(t *testing.T, serverConfig, clientConfig *tls.Config) (tls.ConnectionState, error, testPeerResult) {
	t.Helper()
	listener, err := tls.Listen("tcp", "127.0.0.1:0", serverConfig)
	require.NoError(t, err)
	t.Cleanup(func() { _ = listener.Close() })
	results := make(chan testPeerResult, 1)
	const payload = "ephemeral mutual TLS\n"
	const acknowledgement = "authenticated\n"
	go func() {
		connection, acceptErr := listener.Accept()
		if acceptErr != nil {
			results <- testPeerResult{err: acceptErr}
			return
		}
		defer connection.Close()
		tlsConnection := connection.(*tls.Conn)
		if deadlineErr := tlsConnection.SetDeadline(time.Now().Add(3 * time.Second)); deadlineErr != nil {
			results <- testPeerResult{err: deadlineErr}
			return
		}
		handshakeErr := tlsConnection.Handshake()
		result := testPeerResult{state: tlsConnection.ConnectionState(), err: handshakeErr}
		if handshakeErr == nil {
			data := make([]byte, len(payload))
			_, result.err = io.ReadFull(tlsConnection, data)
			if result.err == nil {
				result.payload = string(data)
				_, result.err = io.WriteString(tlsConnection, acknowledgement)
			}
		}
		results <- result
	}()
	connection, clientErr := tls.DialWithDialer(
		&net.Dialer{Timeout: 3 * time.Second}, "tcp", listener.Addr().String(), clientConfig)
	var state tls.ConnectionState
	if connection != nil {
		defer connection.Close()
		state = connection.ConnectionState()
		clientErr = connection.SetDeadline(time.Now().Add(3 * time.Second))
		if clientErr == nil {
			_, clientErr = io.WriteString(connection, payload)
		}
		if clientErr == nil {
			ack := make([]byte, len(acknowledgement))
			_, clientErr = io.ReadFull(connection, ack)
			if clientErr == nil && string(ack) != acknowledgement {
				clientErr = fmt.Errorf("unexpected acknowledgement: %q", ack)
			}
		}
	}
	select {
	case result := <-results:
		return state, clientErr, result
	case <-time.After(4 * time.Second):
		t.Fatal("loopback peer did not terminate within its deadline")
		return state, clientErr, testPeerResult{}
	}
}
