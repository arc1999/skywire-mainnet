package visor

import (
	"errors"
	"fmt"
	"github.com/SkycoinProject/dmsg"
	"github.com/SkycoinProject/dmsg/cipher"
	"github.com/SkycoinProject/dmsg/dmsgpty"
	"github.com/SkycoinProject/skywire-mainnet/internal/vpn"
	"github.com/SkycoinProject/skywire-mainnet/pkg/app/appdisc"
	"github.com/SkycoinProject/skywire-mainnet/pkg/app/appserver"
	"github.com/SkycoinProject/skywire-mainnet/pkg/app/launcher"
	"github.com/SkycoinProject/skywire-mainnet/pkg/restart"
	"github.com/SkycoinProject/skywire-mainnet/pkg/routefinder/rfclient"
	"github.com/SkycoinProject/skywire-mainnet/pkg/router"
	"github.com/SkycoinProject/skywire-mainnet/pkg/setup/setupclient"
	"github.com/SkycoinProject/skywire-mainnet/pkg/skyenv"
	"github.com/SkycoinProject/skywire-mainnet/pkg/snet"
	"github.com/SkycoinProject/skywire-mainnet/pkg/transport"
	"github.com/SkycoinProject/skywire-mainnet/pkg/transport/tpdclient"
	"github.com/SkycoinProject/skywire-mainnet/pkg/util/updater"
	"net"
	"os"
	"path/filepath"
	"time"
)

func initRestartAndUpdater(v *Visor, restartCtx *restart.Context) bool {
	report := v.reporter("restart")

	restartCheckDelay, err := time.ParseDuration(v.conf.RestartCheckDelay)
	if err != nil {
		return report(err)
	}

	restartCtx.SetCheckDelay(restartCheckDelay)
	restartCtx.RegisterLogger(v.log)

	v.restartCtx = restartCtx
	v.updater = updater.New(v.log, restartCtx, v.conf.Launcher.BinPath)
	return report(nil)
}

func initSNet(v *Visor) bool {
	report := v.reporter("dmsg/stcp")

	n := snet.New(snet.Config{
		PubKey: v.conf.KeyPair.PubKey,
		SecKey: v.conf.KeyPair.SecKey,
		Dmsg:   v.conf.Dmsg,
		STCP:   v.conf.STCP,
	})
	if err := n.Init(v.ctx); err != nil {
		return report(err)
	}
	go func() {
		<-v.ctx.Done()
		report(n.Close())
	}()

	v.net = n
	return report(nil)
}

func initDmsgpty(v *Visor) bool {
	report := v.reporter("dmsgpty")
	conf := v.conf.Dmsgpty

	if conf == nil {
		v.log.Info("'dmsgpty' is not configured, skipping.")
		return report(nil)
	}

	var wl dmsgpty.Whitelist
	if conf.AuthFile == "" {
		wl = dmsgpty.NewMemoryWhitelist()
	} else {
		var err error
		if wl, err = dmsgpty.NewJSONFileWhiteList(v.conf.Dmsgpty.AuthFile); err != nil {
			return report(err)
		}
	}

	dmsgC := v.net.Dmsg()
	if dmsgC == nil {
		return report(errors.New("cannot create dmsgpty with nil dmsg client"))
	}

	pty := dmsgpty.NewHost(dmsgC, wl)

	if ptyPort := conf.Port; ptyPort != 0 {
		v.wg.Add(1)
		go func() {
			defer v.wg.Done()
			if err := pty.ListenAndServe(v.ctx, ptyPort); err != nil {
				report(fmt.Errorf("listen and serve stopped: %w", err))
			}
		}()
	}

	if conf.CLINet != "" {
		if conf.CLINet == "unix" {
			if err := os.MkdirAll(filepath.Dir(conf.CLIAddr), ownerRWX); err != nil {
				return report(fmt.Errorf("failed to prepare unix file for dmsgpty cli listener: %w", err))
			}
		}

		cliL, err := net.Listen(conf.CLINet, conf.CLIAddr)
		if err != nil {
			return report(fmt.Errorf("failed to start dmsgpty cli listener: %w", err))
		}
		go func() {
			<-v.ctx.Done()
			report(cliL.Close())
		}()

		v.wg.Add(1)
		go func() {
			defer v.wg.Done()
			if err := pty.ServeCLI(v.ctx, cliL); err != nil {
				report(fmt.Errorf("serve cli stopped: %w", err))
			}
		}()
	}

	v.pty = pty
	return report(nil)
}

func initTransport(v *Visor) bool {
	report := v.reporter("transport")
	conf := v.conf.Transport

	tpdC, err := tpdclient.NewHTTP(conf.Discovery, v.conf.KeyPair.PubKey, v.conf.KeyPair.SecKey)
	if err != nil {
		return report(fmt.Errorf("failed to create transport discovery client: %w", err))
	}

	var logS transport.LogStore
	switch conf.LogStore.Type {
	case LogStoreFile:
		logS, err = transport.FileTransportLogStore(conf.LogStore.Location)
		if err != nil {
			return report(fmt.Errorf("failed to create %s log store: %w", LogStoreFile, err))
		}
	case LogStoreMemory:
		logS = transport.InMemoryTransportLogStore()
	default:
		return report(fmt.Errorf("invalid log store type: %s", conf.LogStore.Type))
	}

	tpMConf := transport.ManagerConfig{
		PubKey:          v.conf.KeyPair.PubKey,
		SecKey:          v.conf.KeyPair.SecKey,
		DefaultVisors:   conf.TrustedVisors,
		DiscoveryClient: tpdC,
		LogStore:        logS,
	}

	tpM, err := transport.NewManager(v.net, &tpMConf)
	if err != nil {
		return report(fmt.Errorf("failed to start transport manager: %w", err))
	}
	go func() {
		<-v.ctx.Done()
		report(tpM.Close())
	}()

	v.wg.Add(1)
	go func() {
		defer v.wg.Done()
		tpM.Serve(v.ctx)
	}()

	v.tpM = tpM
	return report(nil)
}

func initRouter(v *Visor) bool {
	report := v.reporter("router")
	conf := v.conf.Routing

	rConf := router.Config{
		Logger:           v.MasterLogger().PackageLogger("router"),
		PubKey:           v.conf.KeyPair.PubKey,
		SecKey:           v.conf.KeyPair.SecKey,
		TransportManager: v.tpM,
		RouteFinder:      rfclient.NewHTTP(conf.RouteFinder, time.Duration(conf.RouteFinderTimeout)),
		RouteGroupDialer: setupclient.NewSetupNodeDialer(),
		SetupNodes:       conf.SetupNodes,
		RulesGCInterval:  0, // TODO
	}
	r, err := router.New(v.net, &rConf)
	if err != nil {
		return report(fmt.Errorf("failed to create router: %w", err))
	}

	v.wg.Add(1)
	go func() {
		defer v.wg.Done()
		if err := r.Serve(v.ctx); err != nil {
			report(fmt.Errorf("serve router stopped: %w", err))
		}
	}()

	v.router = r
	return report(nil)
}

func initLauncher(v *Visor) bool {
	report := v.reporter("launcher")
	conf := v.conf.Launcher

	// Prepare app discovery factory.
	factory := appdisc.Factory{ Log: v.MasterLogger().PackageLogger("app_disc") }
	if conf.Discovery != nil {
		factory.PK = v.conf.KeyPair.PubKey
		factory.SK =  v.conf.KeyPair.SecKey
		factory.UpdateInterval = time.Duration(conf.Discovery.UpdateInterval)
		factory.ProxyDisc = conf.Discovery.ProxyDisc
	}

	// Prepare proc manager.
	procMLog := v.MasterLogger().PackageLogger("proc_manager")
	procM, err := appserver.NewProcManager(procMLog, &factory, conf.ServerAddr)
	if err != nil {
		return report(fmt.Errorf("failed to start proc_manager: %w", err))
	}
	v.wg.Add(1)
	go func() {
		defer v.wg.Done()
		<-v.ctx.Done()
		report(procM.Close())
	}()

	// Prepare launcher.
	launchConf := launcher.Config{
		VisorPK:    v.conf.KeyPair.PubKey,
		Apps:       conf.Apps,
		ServerAddr: conf.ServerAddr,
		BinPath:    conf.BinPath,
		LocalPath:  conf.LocalPath,
	}
	launchLog := v.MasterLogger().PackageLogger("launcher")
	launch, err := launcher.NewLauncher(launchLog, launchConf, v.net.Dmsg(), v.router, v.procM)
	if err != nil {
		return report(fmt.Errorf("failed to start launcher: %w", err))
	}
	launch.AutoStart(map[string]func() []string {
		skyenv.VPNClientName: func() []string { return makeVPNEnvs(v.conf, v.net) },
		skyenv.VPNServerName: func() []string { return makeVPNEnvs(v.conf, v.net) },
	})

	v.procM = procM
	v.launch = launch
	return report(nil)
}

func makeVPNEnvs(conf *Config, n *snet.Network) []string {
	var envCfg vpn.DirectRoutesEnvConfig

	if conf.Dmsg != nil {
		envCfg.DmsgDiscovery = conf.Dmsg.Discovery
		envCfg.DmsgServers = n.Dmsg().ConnectedServers()
	}
	if conf.Transport != nil {
		envCfg.TPDiscovery = conf.Transport.Discovery
	}
	if conf.Routing != nil {
		envCfg.RF = conf.Routing.RouteFinder
	}
	if conf.UptimeTracker != nil {
		envCfg.UptimeTracker = conf.UptimeTracker.Addr
	}
	if conf.STCP != nil && len(conf.STCP.PKTable) != 0 {
		envCfg.STCPTable = conf.STCP.PKTable
	}

	envMap := vpn.AppEnvArgs(envCfg)

	envs := make([]string, 0, len(envMap))
	for k, v := range vpn.AppEnvArgs(envCfg) {
		envs = append(envs, fmt.Sprintf("%s=%s", k, v))
	}
	return envs
}

func initCLI(v *Visor) bool {
	report := v.reporter("cli")

	if v.conf.CLIAddr == "" {
		v.log.Info("'cli_addr' is not configured, skipping.")
		return report(nil)
	}

	cliL, err := net.Listen("tcp", v.conf.CLIAddr)
	if err != nil {
		return report(err)
	}
	go func() {
		<-v.ctx.Done()
		report(cliL.Close())
	}()

	rpcS, err := newRPCServer(v, "CLI")
	if err != nil {
		return report(fmt.Errorf("failed to start rpc server for cli: %w", err))
	}
	go rpcS.Accept(cliL) // We not not use sync.WaitGroup here as it will never return anyway.

	return report(nil)
}

func initHypervisors(v *Visor) bool {
	report := v.reporter("hypervisor")

	v.hvErrs = make(map[cipher.PubKey]chan error, len(v.conf.Hypervisors))
	for _, hv := range v.conf.Hypervisors {
		v.hvErrs[hv.PubKey] = make(chan error, 1)
	}

	for hvPK, hvErrs := range v.hvErrs {
		log := v.MasterLogger().PackageLogger("hypervisor_client").WithField("hypervisor_pk", hvPK)

		addr := dmsg.Addr{PK: hvPK, Port: skyenv.DmsgHypervisorPort}
		rpcS, err := newRPCServer(v, addr.PK.String()[:shortHashLen])
		if err != nil {
			return report(fmt.Errorf("failed to start RPC server for hypervisor %s: %w", hvPK, err))
		}

		v.wg.Add(1)
		go func(hvErrs chan error) {
			defer v.wg.Done()
			ServeRPCClient(v.ctx, log, v.net, rpcS, addr, hvErrs)
		}(hvErrs)
	}

	return report(nil)
}
