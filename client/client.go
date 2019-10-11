package main

import (
	"bufio"
	"context"
	"crypto/tls"
	"crypto/x509"
	"io/ioutil"
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
	runClient(ctx)
}

func runClient(ctx context.Context) {
	tlsConfig := setupTLS()
	conn, err := tls.Dial("tcp", utils.Settings.GetString("addr"), tlsConfig)
	if err != nil {
		utils.Logger.Panic("try to dial tcp got error", zap.Error(err))
	}
	defer conn.Close()
	utils.Logger.Info("connected to remote", zap.String("remote", conn.RemoteAddr().String()))

	writer := bufio.NewWriter(conn)
	utils.Logger.Info("start writing")
	for { // send data
		utils.Logger.Info("sending...")
		if _, err = writer.WriteString("hello, world\n"); err != nil {
			utils.Logger.Panic("try to write got error", zap.Error(err))
		}
		if err = writer.Flush(); err != nil {
			utils.Logger.Panic("try to flush got error", zap.Error(err))
		}
		time.Sleep(1 * time.Second)
	}
}
