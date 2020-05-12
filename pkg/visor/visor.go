// Package visor implements skywire visor.
package visor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"github.com/SkycoinProject/skywire-mainnet/pkg/app/launcher"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/SkycoinProject/dmsg"
	"github.com/SkycoinProject/dmsg/cipher"
	"github.com/SkycoinProject/dmsg/dmsgpty"
	"github.com/SkycoinProject/skycoin/src/util/logging"

	"github.com/SkycoinProject/skywire-mainnet/internal/vpn"
	"github.com/SkycoinProject/skywire-mainnet/pkg/app/appcommon"
	"github.com/SkycoinProject/skywire-mainnet/pkg/app/appdisc"
	"github.com/SkycoinProject/skywire-mainnet/pkg/app/appnet"
	"github.com/SkycoinProject/skywire-mainnet/pkg/app/appserver"
	"github.com/SkycoinProject/skywire-mainnet/pkg/restart"
	"github.com/SkycoinProject/skywire-mainnet/pkg/routefinder/rfclient"
	"github.com/SkycoinProject/skywire-mainnet/pkg/router"
	"github.com/SkycoinProject/skywire-mainnet/pkg/routing"
	"github.com/SkycoinProject/skywire-mainnet/pkg/skyenv"
	"github.com/SkycoinProject/skywire-mainnet/pkg/snet"
	"github.com/SkycoinProject/skywire-mainnet/pkg/transport"
	"github.com/SkycoinProject/skywire-mainnet/pkg/util/pathutil"
	"github.com/SkycoinProject/skywire-mainnet/pkg/util/updater"
)

var (
	// ErrAppProcNotRunning represents lookup error for App related calls.
	ErrAppProcNotRunning = errors.New("no process of given app is running")
)

const (
	supportedProtocolVersion = "0.1.0"
	ownerRWX                 = 0700
	shortHashLen             = 6
)

// Visor provides messaging runtime for Apps by setting up all
// necessary connections and performing messaging gateway functions.
type Visor struct {
	ctx  context.Context
	cancel context.CancelFunc // cancel is to be called when visor.Close is triggered
	wg   *sync.WaitGroup
	errCh chan vErr
	log  *logging.Logger

	conf *Config

	net    *snet.Network
	pty    *dmsgpty.Host
	tpM    *transport.Manager
	router router.Router

	procM  appserver.ProcManager
	launch *launcher.Launcher

	startedAt  time.Time
	restartCtx *restart.Context
	updater    *updater.Updater

	cliLis net.Listener
	hvErrs map[cipher.PubKey]chan error // errors returned when the associated hypervisor ServeRPCClient returns
}

type vErr struct {
	err error
	src string
}

func (v *Visor) reporter(src string) func(err error) bool {
	return func(err error) bool {
		v.errCh <- vErr{src: src, err: err}
		return err == nil
	}
}

func (v *Visor) processReports(ok *bool) {
	for {
		select {
		case ve := <- v.errCh:
			if ve.err != nil {
				v.log.WithError(ve.err).WithField("_src", ve.src).Error()
				*ok = false
			}
		default:
			return
		}
	}
}

// MasterLogger returns the underlying master logger (currently contained in visor config).
func (v *Visor) MasterLogger() *logging.MasterLogger {
	return v.conf.log
}

// NewVisor constructs new Visor.
func NewVisor(ctx context.Context, conf *Config, restartCtx *restart.Context) (v *Visor, ok bool) {
	ctx, cancel := context.WithCancel(ctx)

	v = &Visor{
		ctx:  ctx,
		cancel: cancel,
		wg:   new(sync.WaitGroup),
		errCh: make(chan vErr, 100),
		log:  conf.log.PackageLogger("v"),
		conf: conf,
	}

	if lvl, err := logging.LevelFromString(conf.LogLevel); err == nil {
		v.conf.log.SetLevel(lvl)
	}

	v.log.WithField("public_key", conf.KeyPair.PubKey).Info("Starting...")
	v.startedAt = time.Now()

	defer v.processReports(&ok)

	if !initRestartAndUpdater(v, restartCtx) {
		return v, false
	}
	if !initSNet(v) {
		return v, false
	}
	if !initDmsgpty(v) {
		return v, false
	}
	if !initTransport(v) {
		return v, false
	}
	if !initRouter(v) {
		return v, false
	}
	if !initLauncher(v) {
		return v, false
	}
	if !initCLI(v) {
		return v, false
	}
	if !initHypervisors(v) {
		return v, false
	}

	return v, ok
}

// Close safely stops spawned Apps and Visor.
func (v *Visor) Close() error {
	if v == nil {
		return nil
	}

	v.cancel()
	v.wg.Wait()

	var ok bool
	v.processReports(&ok)
	return nil
}

// Exec executes a shell command. It returns combined stdout and stderr output and an error.
func (v *Visor) Exec(command string) ([]byte, error) {
	args := strings.Split(command, " ")
	cmd := exec.Command(args[0], args[1:]...) // nolint: gosec
	return cmd.CombinedOutput()
}

// Update updates visor.
// It checks if visor update is available.
// If it is, the method downloads a new visor versions, starts it and kills the current process.
func (v *Visor) Update() (bool, error) {
	updated, err := v.updater.Update()
	if err != nil {
		v.log.Errorf("Failed to update visor: %v", err)
		return false, err
	}

	return updated, nil
}

// UpdateAvailable checks if visor update is available.
func (v *Visor) UpdateAvailable() (*updater.Version, error) {
	version, err := v.updater.UpdateAvailable()
	if err != nil {
		v.log.Errorf("Failed to check if visor update is available: %v", err)
		return nil, err
	}

	return version, nil
}

func (v *Visor) setAutoStart(appName string, autoStart bool) error {
	appConf, ok := v.appsConf[appName]
	if !ok {
		return ErrAppProcNotRunning
	}

	appConf.AutoStart = autoStart
	v.appsConf[appName] = appConf

	v.log.Infof("Saving auto start = %v for app %v to config", autoStart, appName)

	return v.updateAppAutoStart(appName, autoStart)
}

func (v *Visor) setSocksPassword(password string) error {
	v.log.Infof("Changing skysocks password to %q", password)

	const (
		socksName       = "skysocks"
		passcodeArgName = "-passcode"
	)

	if err := v.updateAppArg(socksName, passcodeArgName, password); err != nil {
		return err
	}

	if _, ok := v.procM.ProcByName(socksName); ok {
		v.log.Infof("Updated %v password, restarting it", socksName)
		return v.RestartApp(socksName)
	}

	v.log.Infof("Updated %v password", socksName)

	return nil
}

func (v *Visor) setSocksClientPK(pk cipher.PubKey) error {
	v.log.Infof("Changing skysocks-client PK to %q", pk)

	const (
		socksClientName = "skysocks-client"
		pkArgName       = "-srv"
	)

	if err := v.updateAppArg(socksClientName, pkArgName, pk.String()); err != nil {
		return err
	}

	if _, ok := v.procM.ProcByName(socksClientName); ok {
		v.log.Infof("Updated %v PK, restarting it", socksClientName)
		return v.RestartApp(socksClientName)
	}

	v.log.Infof("Updated %v PK", socksClientName)

	return nil
}

func (v *Visor) updateAppAutoStart(appName string, autoStart bool) error {
	changed := false

	for i := range v.conf.Apps {
		if v.conf.Apps[i].App == appName {
			v.conf.Apps[i].AutoStart = autoStart
			if v, ok := v.appsConf[appName]; ok {
				v.AutoStart = autoStart
				v.appsConf[appName] = v
			}

			changed = true
			break
		}
	}

	if !changed {
		return nil
	}

	return v.conf.Flush()
}

func (v *Visor) updateAppArg(appName, argName, value string) error {
	configChanged := true

	for i := range v.conf.Apps {
		argChanged := false
		if v.conf.Apps[i].App == appName {
			configChanged = true

			for j := range v.conf.Apps[i].Args {
				if v.conf.Apps[i].Args[j] == argName && j+1 < len(v.conf.Apps[i].Args) {
					v.conf.Apps[i].Args[j+1] = value
					argChanged = true
					break
				}
			}

			if !argChanged {
				v.conf.Apps[i].Args = append(v.conf.Apps[i].Args, argName, value)
			}

			if v, ok := v.appsConf[appName]; ok {
				v.Args = v.conf.Apps[i].Args
				v.appsConf[appName] = v
			}
		}
	}

	if configChanged {
		return v.conf.Flush()
	}

	return nil
}

// UnlinkSocketFiles removes unix socketFiles from file system
func UnlinkSocketFiles(socketFiles ...string) error {
	for _, f := range socketFiles {
		if err := syscall.Unlink(f); err != nil {
			if !strings.Contains(err.Error(), "no such file or directory") {
				return err
			}
		}
	}

	return nil
}
