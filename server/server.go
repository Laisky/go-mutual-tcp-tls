package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"net"
	"sync/atomic"
	"time"

	middlewares "github.com/Laisky/go-utils/gin-middlewares"

	"github.com/gin-contrib/pprof"
	"github.com/gin-gonic/gin"

	"github.com/spf13/pflag"

	"github.com/Laisky/go-utils"
	"github.com/Laisky/zap"
)

func setupArgs() {
	pflag.Bool("debug", false, "run in debug mode")
	pflag.String("ca", "ca.crt", "ca file path")                       // CA, to verify client's cert
	pflag.String("crt", "server.crt", "server crt file path")          // server cert
	pflag.String("crt-key", "server.key.text", "server key file path") // server key
	pflag.String("addr", "localhost:24444", "server listening port")
	pflag.String("http-addr", "localhost:8080", "http listening port")
	pflag.Parse()
	utils.Settings.BindPFlags(pflag.CommandLine)

	if utils.Settings.GetBool("debug") {
		utils.SetupLogger("debug")
		utils.Logger.Info("run in debug mode")
	} else { // prod mode
		utils.SetupLogger("info")
		utils.Logger.Info("run in prod mode")
	}
}

func setupTLS() *tls.Config {
	utils.Logger.Info("load key & crt",
		zap.String("crt", utils.Settings.GetString("crt")),
		zap.String("crt-key", utils.Settings.GetString("crt-key")),
	)
	srvCert, err := tls.LoadX509KeyPair(utils.Settings.GetString("crt"), utils.Settings.GetString("crt-key"))
	if err != nil {
		utils.Logger.Panic("try to load key & crt got error", zap.Error(err))
	}

	// load ca
	utils.Logger.Info("load ca", zap.String("ca", utils.Settings.GetString("ca")))
	caCrt, err := ioutil.ReadFile(utils.Settings.GetString("ca"))
	if err != nil {
		utils.Logger.Panic("try to load ca got error", zap.Error(err))
	}
	caCertPool := x509.NewCertPool()
	caCertPool.AppendCertsFromPEM(caCrt)

	// cnt, _ := ioutil.ReadFile(utils.Settings.GetString("crt"))
	// fmt.Println(string(cnt))
	// cnt, _ = ioutil.ReadFile(utils.Settings.GetString("crt-key"))
	// fmt.Println(string(cnt))
	// fmt.Println(string(caCrt))

	// https tls config
	tlsConfig := &tls.Config{
		Certificates:       []tls.Certificate{srvCert},
		ClientCAs:          caCertPool,                     // CA pool to verify clients' cert
		InsecureSkipVerify: false,                          // must verify
		ClientAuth:         tls.RequireAndVerifyClientCert, // client must has verified cert
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig
}

func main() {
	setupArgs()
	ctx := context.Background()
	nConn := int64(0)
	go runHeartBeat(ctx, &nConn)
	go runMetric()
	runListener(ctx, &nConn)
}

func runMetric() {
	s := gin.New()
	pprof.Register(s, "pprof")
	middlewares.BindPrometheus(s)
	utils.Logger.Info("listening on http", zap.String("http-addr", utils.Settings.GetString("http-addr")))
	utils.Logger.Panic("server exit", zap.Error(s.Run(utils.Settings.GetString("http-addr"))))
}

func runHeartBeat(ctx context.Context, nConn *int64) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			utils.Logger.Info("heartbeat", zap.Int64("conn", atomic.LoadInt64(nConn)))
			time.Sleep(5 * time.Second)
		}
	}
}

func runListener(ctx context.Context, nConn *int64) {
	tlsConfig := setupTLS()

LISTEN_LOOP:
	for {
		select {
		case <-ctx.Done():
			break LISTEN_LOOP
		default:
		}

		ln, err := tls.Listen("tcp", utils.Settings.GetString("addr"), tlsConfig)
		if err != nil {
			utils.Logger.Error("try to listen tcp got error", zap.Error(err))
			time.Sleep(3 * time.Second)
			continue LISTEN_LOOP
		}
		utils.Logger.Info("listening...", zap.String("addr", utils.Settings.GetString("addr")))

	ACCEPT_LOOP:
		for {
			select {
			case <-ctx.Done():
				break ACCEPT_LOOP
			default:
			}

			conn, err := ln.Accept()
			if err != nil {
				utils.Logger.Error("accept conn got error", zap.Error(err))
				break ACCEPT_LOOP
			}

			atomic.AddInt64(nConn, 1)
			go handle(conn, nConn)
		}
		ln.Close()
	}
}

func showCert(conn net.Conn) {
	var (
		tlsConn *tls.Conn
		ok      bool
		err     error
	)
	if tlsConn, ok = conn.(*tls.Conn); !ok {
		utils.Logger.Error("convert connection to tlsconn got error", zap.Error(err))
	}

	// verify cert
	if err = tlsConn.Handshake(); err != nil {
		utils.Logger.Error("handshake got error", zap.Error(err))
	}

	// print client's cert information
	// state := tlsConn.ConnectionState()
	// utils.Logger.Debug("accept tls connection",
	// 	zap.Uint16("Version", state.Version),
	// 	zap.Bool("HandshakeComplete", state.HandshakeComplete),
	// 	zap.Bool("DidResume", state.DidResume),
	// 	zap.Uint16("CipherSuite", state.CipherSuite),
	// 	zap.String("NegotiatedProtocol", state.NegotiatedProtocol),
	// 	zap.Bool("NegotiatedProtocolIsMutual", state.NegotiatedProtocolIsMutual))
	// for i, cert := range state.PeerCertificates {
	// 	subject := cert.Subject
	// 	issuer := cert.Issuer
	// 	fmt.Printf("    --------------- cert[%d] ---------------\n", i)
	// 	fmt.Printf("    %v s:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s\n", subject.SerialNumber, subject.Country, subject.Province, subject.Locality, subject.Organization, subject.OrganizationalUnit, subject.CommonName)
	// 	fmt.Printf("        i:/C=%v/ST=%v/L=%v/O=%v/OU=%v/CN=%s\n", issuer.Country, issuer.Province, issuer.Locality, issuer.Organization, issuer.OrganizationalUnit, issuer.CommonName)
	// }

}

func handle(conn net.Conn, nConn *int64) {
	utils.Logger.Info("got connection", zap.String("remote", conn.RemoteAddr().String()))
	defer utils.Logger.Info("close connection", zap.String("remote", conn.RemoteAddr().String()))
	defer atomic.AddInt64(nConn, -1)
	defer conn.Close()
	showCert(conn)
	reader := bufio.NewReader(conn)
	var (
		err     error
		content string
	)
	for { // read data from client
		if content, err = reader.ReadString('\n'); err != nil {
			utils.Logger.Warn("try to read got error", zap.Error(err))
			break
		}

		utils.Logger.Debug("got", zap.String("cnt", content))
	}
}
