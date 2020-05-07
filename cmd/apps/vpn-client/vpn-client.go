package main

import (
	"context"
	"flag"
	"net"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/sirupsen/logrus"

	"github.com/SkycoinProject/dmsg/cipher"
	"github.com/SkycoinProject/dmsg/netutil"

	"github.com/SkycoinProject/skywire-mainnet/internal/vpn"
	"github.com/SkycoinProject/skywire-mainnet/pkg/app"
	"github.com/SkycoinProject/skywire-mainnet/pkg/app/appnet"
	"github.com/SkycoinProject/skywire-mainnet/pkg/routing"
	"github.com/SkycoinProject/skywire-mainnet/pkg/skyenv"
)

const (
	netType = appnet.TypeSkynet
	vpnPort = routing.Port(skyenv.VPNServerPort)
)

const (
	serverDialInitBO = 1 * time.Second
	serverDialMaxBO  = 10 * time.Second
)

var (
	log = logrus.New()
	r   = netutil.NewRetrier(log, serverDialInitBO, serverDialMaxBO, 0, 1)
)

var serverPKStr = flag.String("srv", "", "PubKey of the server to connect to")

func dialServer(appCl *app.Client, pk cipher.PubKey) (net.Conn, error) {
	var conn net.Conn
	err := r.Do(context.Background(), func() error {
		var err error
		conn, err = appCl.Dial(appnet.Addr{
			Net:    netType,
			PubKey: pk,
			Port:   vpnPort,
		})
		return err
	})
	if err != nil {
		return nil, err
	}

	return conn, nil
}

func main() {
	flag.Parse()

	if *serverPKStr == "" {
		log.Fatalln("VPN server pub key is missing")
	}

	serverPK := cipher.PubKey{}
	if err := serverPK.UnmarshalText([]byte(*serverPKStr)); err != nil {
		log.WithError(err).Fatalln("Invalid VPN server pub key")
	}

	appClient := app.NewClient()
	defer appClient.Close()

	log.Infof("Connecting to VPN server %s", serverPK.String())

	appConn, err := dialServer(appClient, serverPK)
	if err != nil {
		log.WithError(err).Fatalln("Error connecting to VPN server")
	}
	defer func() {
		if err := appConn.Close(); err != nil {
			log.WithError(err).Errorln("Error closing connection to the VPN server")
		}
	}()

	log.Infof("Dialed %s", appConn.RemoteAddr())

	vpnClient, err := vpn.NewClient(log, appConn)
	if err != nil {
		log.WithError(err).Fatalln("Error creating VPN client")
	}

	osSigs := make(chan os.Signal, 2)
	sigs := []os.Signal{syscall.SIGTERM, syscall.SIGINT}
	for _, sig := range sigs {
		signal.Notify(osSigs, sig)
	}

	go func() {
		<-osSigs
		vpnClient.Close()
	}()

	if err := vpnClient.Serve(); err != nil {
		log.WithError(err).Fatalln("Error serving VPN")
	}
}
