package boundary

import (
	ur "codehub-y.huawei.com/CloudSOP/GoF2/http"
	"encoding/json"
	"errors"
	"golang.org/x/sys/unix"
	"kernel-installer/util"
	"net/http"
	"os"
	"path/filepath"
	"syscall"
	"unsafe"
)

const ()

var CEI *ceiAdapt

const (
	uuidFile   = "/var/run/secrets/fustionstage.io/serviceaccount/uuid"
	tokenFile  = "/var/run/secrets/fustionstage.io/serviceaccount/token"
	rootCAFile = "/var/run/secrets/fustionstage.io/serviceaccount/ca.crt"
)

type Identity struct {
	UUID      string `json:"uuid"`
	Cipher    string `json:"cipher"`
	PodName   string `json:"-"`
	Namespace string `json:"-"`
}

type decryptResult struct {
	plain string
}

type ceiAdapt struct {
	ceiSockAddress string
	identity       Identity
	fw             *fileWatcher
}

type Decrypt interface {
	GetDecryptPlain() (string, error)
}

type Inotify interface {
	Init()
	Register(string, uint32, func())
	ReadEvents()
	Close()
}

type FileEvent struct {
	file  int
	event uint32
}

type fileWatcher struct {
	Events chan FileEvent
	Stop   chan struct{}
	//mu           sync.Mutex
	handler      map[int]func()
	KeepWatching bool
}

func NewFileWatcher() *fileWatcher {
	fw := &fileWatcher{Events: make(chan FileEvent, 10)}
	go fw.Init()
	go fw.ReadEvents()
	return fw
}

func (fw *fileWatcher) Init() {
	defer func() {
		for fd, _ := range fw.handler {
			_ = unix.Close(fd)
		}
		fw.Stop <- struct{}{}
	}()

	for fw.KeepWatching {
		for fd, _ := range fw.handler {
			var buf [unix.SizeofInotifyEvent * 16]byte
			n, err := unix.Read(fd, buf[:])
			if err != nil {
				n = 0
				continue
			}

			for unix.SizeofInotifyEvent <= uint32(n) {
				raw := (*unix.InotifyEvent)(unsafe.Pointer(&buf[0]))
				mask := uint32(raw.Mask)
				fw.Events <- FileEvent{fd, mask}
			}
		}
	}
}

func (fw *fileWatcher) Register(path string, mask uint32, handler func()) {
	fd, err := unix.InotifyInit()
	if err != nil {
		util.ConsoleLogger.Logf(util.ERROR, "failed to init unix inotify: %v", err)
		return
	}
	_, err = unix.InotifyAddWatch(fd, path, mask)
	fw.handler[fd] = handler
	if err != nil {
		return
	}

}

func (fw *fileWatcher) ReadEvents() {
	defer func() {
		close(fw.Events)
		close(fw.Stop)
	}()

	for {
		select {
		case event := <-fw.Events:
			if event.event&syscall.IN_CLOSE_WRITE == syscall.IN_CLOSE_WRITE {
				fw.handler[event.file]()
			}
		case <-fw.Stop:
			return
		}
	}
}

func (fw *fileWatcher) Close() {
	fw.KeepWatching = false
}

func (c *ceiAdapt) GetDecryptPlain() (string, error) {
	client := ur.NewClient()
	status, response, udsError := client.SendWithHeader(
		http.MethodGet,
		c.ceiSockAddress,
		http.Header{
			"podName":   []string{c.identity.PodName},
			"namespace": []string{c.identity.Namespace},
		},
		c.identity,
	)

	if status != http.StatusOK || udsError != nil {
		util.ConsoleLogger.Logf(util.ERROR, "failed to read decrypted cipher: %v", udsError)
		return "", errors.New("")
	}

	var resp decryptResult
	if decodeError := json.Unmarshal(response, &resp); decodeError != nil {
		util.ConsoleLogger.Logf(util.ERROR, "failed to read decrypted cipher: %s", decodeError.Error())
		return "", decodeError
	}

	return resp.plain, nil
}

func InitCEIAdapterAdapt() error {
	CEI = &ceiAdapt{
		ceiSockAddress: filepath.Join(os.Getenv("CEI_ROOT"), "uds/cei.sock"),
		identity: Identity{
			PodName:   Envs.GetPodName(),
			Namespace: Envs.GetNamespace(),
		},
		fw: NewFileWatcher(),
	}

	if _, err := os.Stat(CEI.ceiSockAddress); err != nil && os.IsNotExist(err) {
		util.ConsoleLogger.Logf(util.ERROR, "read cei socket failed: %v", err.Error())
		return err
	}
	CEI.GetUUID()

	// TODO: read first, and update it periodically, but when to exit?
	CEI.UpdateCipher()
	CEI.fw.Register(tokenFile, syscall.IN_CLOSE_WRITE, CEI.UpdateCipher)

	return nil
}

func (c *ceiAdapt) UpdateCipher() {
	if file, err := util.FileUtil.ReadFile(tokenFile); err == nil {
		c.identity.Cipher = string(file)
	}
}

func (c *ceiAdapt) GetUUID() {
	if uuid, err := util.FileUtil.ReadFile(uuidFile); err == nil {
		c.identity.UUID = string(uuid)
	}
}
