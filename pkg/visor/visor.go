// Package visor implements skywire visor.
package visor

import (
	"errors"
	"fmt"
	"net"
	"os/exec"
	"runtime"
	"strings"
	"syscall"
	"time"
	"unsafe"

	"github.com/sirupsen/logrus"

	"github.com/SkycoinProject/skywire-mainnet/pkg/app/launcher"

	"github.com/SkycoinProject/dmsg/cipher"
	"github.com/SkycoinProject/dmsg/dmsgpty"
	"github.com/SkycoinProject/skycoin/src/util/logging"

	"github.com/SkycoinProject/skywire-mainnet/pkg/app/appserver"
	"github.com/SkycoinProject/skywire-mainnet/pkg/restart"
	"github.com/SkycoinProject/skywire-mainnet/pkg/router"
	"github.com/SkycoinProject/skywire-mainnet/pkg/snet"
	"github.com/SkycoinProject/skywire-mainnet/pkg/transport"
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
	//ctx      context.Context
	//cancel   context.CancelFunc // cancel is to be called when visor.Close is triggered
	//wg       *sync.WaitGroup

	reportCh   chan vReport
	closeStack []closeElem

	conf *Config
	log  *logging.Logger

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

type vReport struct {
	src string
	err error
}

type reportFunc func(err error) bool

func (v *Visor) makeReporter(src string) reportFunc {
	return func(err error) bool {
		v.reportCh <- vReport{src: src, err: err}
		return err == nil
	}
}

func (v *Visor) processReports(log logrus.FieldLogger, ok *bool) {
	if log == nil {
		log = v.log
	}
	for {
		select {
		case report := <-v.reportCh:
			if report.err != nil {
				v.log.WithError(report.err).WithField("_src", report.src).Error()
				*ok = false
			}
		default:
			return
		}
	}
}

type closeElem struct {
	src string
	fn  func() bool
}

func (v *Visor) pushCloseStack(src string, fn func() bool) {
	v.closeStack = append(v.closeStack, closeElem{src: src, fn: fn})
}

// MasterLogger returns the underlying master logger (currently contained in visor config).
func (v *Visor) MasterLogger() *logging.MasterLogger {
	return v.conf.log
}

// NewVisor constructs new Visor.
func NewVisor(conf *Config, restartCtx *restart.Context) (v *Visor, ok bool) {
	v = &Visor{
		reportCh:   make(chan vReport, 100),
		log:        conf.log.PackageLogger("v"),
		conf:       conf,
		restartCtx: restartCtx,
	}

	if lvl, err := logging.LevelFromString(conf.LogLevel); err == nil {
		v.conf.log.SetLevel(lvl)
	}

	v.log.WithField("public_key", conf.KeyPair.PubKey).Info("Starting visor.")
	v.startedAt = time.Now()

	startStack := []startFunc{
		initRestartAndUpdater,
		initSNet,
		initDmsgpty,
		initTransport,
		initRouter,
		initLauncher,
		initCLI,
		initHypervisors,
		initUptimeTracker,
	}

	log := v.MasterLogger().PackageLogger("visor.startup")

	for i, startFn := range startStack {
		name := runtime.FuncForPC(uintptr(unsafe.Pointer(&startFn))).Name()
		start := time.Now()

		log := log.
			WithField("name", name).
			WithField("stack", fmt.Sprintf("%d/%d", i+1, len(startStack)))
		log.Info("Starting module...")

		if ok := startFn(v); !ok {
			log.WithField("elapsed", time.Since(start)).Error("Failed to start module.")
			v.processReports(log, &ok)
			return v, ok
		}

		log.WithField("elapsed", time.Since(start)).Info("Module started successfully.")
	}

	return v, ok
}

// Close safely stops spawned Apps and Visor.
func (v *Visor) Close() error {
	if v == nil {
		return nil
	}

	log := v.MasterLogger().PackageLogger("visor.close_stack")
	log.Info("Begin shutdown.")

	for i, ce := range v.closeStack {

		start := time.Now()
		done := make(chan bool, 1)
		t := time.NewTimer(time.Second * 2)

		log := log.
			WithField("name", ce.src).
			WithField("stack", fmt.Sprintf("%d/%d", i+1, len(v.closeStack)))
		log.Info("Closing stack element...")

		go func(ce closeElem) {
			done <- ce.fn()
			close(done)
		}(ce)

		select {
		case ok := <-done:
			if !ok {
				log.WithField("elapsed", time.Since(start)).Warn("Closed with unexpected result.")
				v.processReports(log, &ok)
				continue
			}
			log.WithField("elapsed", time.Since(start)).Info("Closed successfully.")
		case <-t.C:
			log.WithField("elapsed", time.Since(start)).Error("Timeout.")
		}
	}

	var ok bool
	v.processReports(v.log, &ok)
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
	if _, ok := v.launch.AppState(appName); !ok {
		return ErrAppProcNotRunning
	}

	v.log.Infof("Saving auto start = %v for app %v to config", autoStart, appName)
	return v.conf.UpdateAppAutostart(v.launch, appName, autoStart)
}

func (v *Visor) setSocksPassword(password string) error {
	v.log.Infof("Changing skysocks password to %q", password)

	const (
		socksName       = "skysocks"
		passcodeArgName = "-passcode"
	)

	if err := v.conf.UpdateAppArg(v.launch, socksName, passcodeArgName, password); err != nil {
		return err
	}

	if _, ok := v.procM.ProcByName(socksName); ok {
		v.log.Infof("Updated %v password, restarting it", socksName)
		return v.launch.RestartApp(socksName)
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

	if err := v.conf.UpdateAppArg(v.launch, socksClientName, pkArgName, pk.String()); err != nil {
		return err
	}

	if _, ok := v.procM.ProcByName(socksClientName); ok {
		v.log.Infof("Updated %v PK, restarting it", socksClientName)
		return v.launch.RestartApp(socksClientName)
	}

	v.log.Infof("Updated %v PK", socksClientName)

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
