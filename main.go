package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
	"golang.org/x/sys/unix"
)

func main() {
	if err := run(setupHandler()); err != nil {
		fmt.Fprintf(os.Stderr, "error: %s", err.Error())
		os.Exit(1)
	}
	os.Exit(0)
}

func run(ctx context.Context) error {
	var bpfObjects bpfObjects

	executable, err := os.Executable()
	if err != nil {
		return err
	}
	bpfObjectFile := path.Join(filepath.Dir(executable), "daemon.bpf.o")

	spec, err := ebpf.LoadCollectionSpec(bpfObjectFile)
	if err != nil {
		return err
	}
	encoder := &bpfEncoder{byteOrder: spec.ByteOrder}

	err = spec.LoadAndAssign(&bpfObjects, &ebpf.CollectionOptions{})
	if err != nil {
		return err
	}
	defer bpfObjects.Close()

	reader, err := ringbuf.NewReader(bpfObjects.EventsMap)
	if err != nil {
		return err
	}
	defer reader.Close()

	go func() {
		for {
			select {
			case <-ctx.Done():
				return
			default:
				record, err := reader.Read()
				if err != nil {
					if errors.Is(err, ringbuf.ErrClosed) {
						return
					}
					fmt.Fprintf(os.Stderr, "error: failed reading record from ringbuf: %v\n", err)
					continue
				}

				err = parseAndPrintEvent(record.RawSample, encoder)
				if err != nil {
					fmt.Fprintf(os.Stderr, "error: failed parsing and printg event: %v\n", err)
					continue
				}
			}
		}
	}()

	sysEnterExecveLink, err := link.Tracepoint("syscalls", "sys_enter_execve", bpfObjects.SysEnterExecveProg, &link.TracepointOptions{})
	if err != nil {
		return err
	}
	defer sysEnterExecveLink.Close()

	sysExitExecveLink, err := link.Tracepoint("syscalls", "sys_exit_execve", bpfObjects.SysExitExecveProg, &link.TracepointOptions{})
	if err != nil {
		return err
	}
	defer sysExitExecveLink.Close()

	fmt.Println("BPF daemon started")

	<-ctx.Done()

	return nil
}

func parseAndPrintEvent(buf []byte, encoder *bpfEncoder) error {
	e := event{}
	err := e.unpack(buf, encoder)
	if err != nil {
		return fmt.Errorf("failed unpacking event: %w", err)
	}
	j, err := e.toJSON()
	if err != nil {
		return fmt.Errorf("failed converting event to JSON: %w", err)
	}
	_, err = fmt.Println(j)
	return err
}

type bpfObjects struct {
	bpfPrograms
	bpfMaps
}

func (o *bpfObjects) Close() error {
	return bpfClose(
		&o.bpfPrograms,
		&o.bpfMaps,
	)
}

type bpfPrograms struct {
	SysEnterExecveProg *ebpf.Program `ebpf:"sys_enter_execve"`
	SysExitExecveProg  *ebpf.Program `ebpf:"sys_exit_execve"`
}

func (p *bpfPrograms) Close() error {
	return bpfClose(
		p.SysEnterExecveProg,
		p.SysExitExecveProg,
	)
}

type bpfMaps struct {
	EventsMap *ebpf.Map `ebpf:"events"`
}

func (m *bpfMaps) Close() error {
	return bpfClose(
		m.EventsMap,
	)
}

func bpfClose(closers ...io.Closer) error {
	for _, closer := range closers {
		if err := closer.Close(); err != nil {
			return err
		}
	}
	return nil
}

var onlyOneSignalHandler = make(chan struct{})

func setupHandler() context.Context {
	close(onlyOneSignalHandler)

	ctx, cancel := context.WithCancel(context.Background())

	c := make(chan os.Signal, 2)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-c
		cancel()
		<-c
		os.Exit(1)
	}()

	return ctx
}

type event struct {
	Pid       int
	PPid      int
	Comm      string
	Uid       int
	retval    int
	argsCount byte
	argsSize  int
	Args      []string
}

func (e *event) unpack(buf []byte, encoder *bpfEncoder) error {
	var off = 0
	var err error

	e.Pid, off, err = encoder.Uint32AsInt(buf, off)
	if err != nil {
		return err
	}
	e.PPid, off, err = encoder.Uint32AsInt(buf, off)
	if err != nil {
		return err
	}

	e.Comm, off, err = encoder.Str(buf, off, 16)
	if err != nil {
		return err
	}

	e.Uid, off, err = encoder.Uint32AsInt(buf, off)
	if err != nil {
		return err
	}

	e.retval, off, err = encoder.Uint32AsInt(buf, off)
	if err != nil {
		return err
	}

	e.argsCount, off, err = encoder.Byte(buf, off)
	if err != nil {
		return err
	}

	e.argsSize, off, err = encoder.Uint16AsInt(buf, off)
	if err != nil {
		return err
	}

	e.Args, off, err = encoder.Strs(buf, off, e.argsSize)
	if err != nil {
		return err
	}

	return nil
}

func (e *event) toJSON() (string, error) {
	j, err := json.Marshal(e)
	if err != nil {
		return "", err
	}
	return string(j), nil
}

type bpfEncoder struct {
	byteOrder binary.ByteOrder
}

func (e *bpfEncoder) Byte(buf []byte, off int) (byte, int, error) {
	if off+1 > len(buf) {
		return 0, off, errors.New("overflow unpacking byte")
	}
	return buf[off], off + 1, nil
}

func (e *bpfEncoder) Uint16(buf []byte, off int) (uint16, int, error) {
	if off+2 > len(buf) {
		return 0, off, errors.New("overflow unpacking uint16")
	}
	u := e.byteOrder.Uint16(buf[off : off+2])
	return u, off + 2, nil
}

func (e *bpfEncoder) Uint16AsInt(buf []byte, off int) (int, int, error) {
	i, o, err := e.Uint16(buf, off)
	return int(i), o, err
}

func (e *bpfEncoder) Uint32(buf []byte, off int) (uint32, int, error) {
	if off+4 > len(buf) {
		return 0, off, errors.New("overflow unpacking uint32")
	}
	u := e.byteOrder.Uint32(buf[off : off+4])
	return u, off + 4, nil
}

func (e *bpfEncoder) Uint32AsInt(buf []byte, off int) (int, int, error) {
	i, o, err := e.Uint32(buf, off)
	return int(i), o, err
}

func (e *bpfEncoder) Str(buf []byte, off, sz int) (string, int, error) {
	if off+sz > len(buf) {
		return "", off, errors.New("overflow unpacking string")
	}
	s := make([]byte, sz)
	_ = copy(s, buf[off:off+sz])
	return unix.ByteSliceToString(s), off + sz, nil
}

func (e *bpfEncoder) Strs(buf []byte, off, sz int) ([]string, int, error) {
	if off+sz > len(buf) {
		return nil, off, errors.New("overflow unpacking []string")
	}
	copiedBuf := make([]byte, sz)
	var strs []string
	_ = copy(copiedBuf, buf[off:off+sz])
	slices := bytes.Split(copiedBuf, []byte{0})
	for _, slice := range slices {
		if len(slice) == 0 {
			continue
		}
		strs = append(strs, unix.ByteSliceToString(slice))
	}
	return strs, off + sz, nil
}
