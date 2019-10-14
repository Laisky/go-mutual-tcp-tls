package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
	"sync/atomic"
	"time"

	"github.com/Laisky/go-utils"
	"github.com/Laisky/zap"
	"github.com/spf13/pflag"
)

func setupArgs() {
	pflag.Bool("debug", false, "run in debug mode")
	pflag.String("ca", "ca.crt", "ca file path")                       // CA to verify server's cert
	pflag.String("crt", "client.crt", "client crt file path")          // client cert
	pflag.String("crt-key", "client.key.text", "client key file path") // client key
	pflag.String("addr", "localhost:24444", "client dial port")
	pflag.Int("nfork", 1, "how many connections")
	pflag.Parse()
	if err := utils.Settings.BindPFlags(pflag.CommandLine); err != nil {
		utils.Logger.Panic("parse command line arguments", zap.Error(err))
	}

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
	cliCert, err := tls.LoadX509KeyPair(utils.Settings.GetString("crt"), utils.Settings.GetString("crt-key"))
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
		Certificates:       []tls.Certificate{cliCert},
		RootCAs:            caCertPool, // CA pool to verify server's cert
		InsecureSkipVerify: false,      // must verify
	}
	tlsConfig.BuildNameToCertificate()
	return tlsConfig
}

func main() {
	setupArgs()
	ctx := context.Background()
	tlsConfig := setupTLS()
	nConn := int64(0)
	go runHeartBeat(ctx, &nConn)
	for i := 0; i < utils.Settings.GetInt("nfork"); i++ {
		go runClient(ctx, tlsConfig, &nConn)
	}

	<-ctx.Done()
}

func runHeartBeat(ctx context.Context, nConn *int64) {
	for {
		select {
		case <-ctx.Done():
			return
		default:
			utils.Logger.Info("heartbeat", zap.Int64("conn", atomic.LoadInt64(nConn)))
			utils.ForceGCUnBlocking()
			time.Sleep(1 * time.Minute)
		}
	}
}

func runClient(ctx context.Context, tlsConfig *tls.Config, nConn *int64) {
CONN_LOOP:
	for {
		select {
		case <-ctx.Done():
			break CONN_LOOP
		default:
		}

		conn, err := tls.Dial("tcp", utils.Settings.GetString("addr"), tlsConfig)
		if err != nil {
			utils.Logger.Error("try to dial tcp got error", zap.Error(err))
			time.Sleep(3 * time.Second)
			continue CONN_LOOP
		}
		utils.Logger.Info("connected to remote", zap.String("remote", conn.RemoteAddr().String()))
		atomic.AddInt64(nConn, 1)

		writer := bufio.NewWriter(conn)
	SEND_LOOP:
		for { // send data
			select {
			case <-ctx.Done():
				break SEND_LOOP
			default:
			}

			utils.Logger.Debug("sending...")
			if _, err = writer.WriteString("hello, world\n"); err != nil {
				utils.Logger.Error("try to write got error", zap.Error(err))
				break SEND_LOOP
			}
			if err = writer.Flush(); err != nil {
				utils.Logger.Error("try to flush got error", zap.Error(err))
				break SEND_LOOP
			}
			time.Sleep(1 * time.Second)
		}

		atomic.AddInt64(nConn, -1)
		conn.Close()
	}
}
