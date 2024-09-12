package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"path"
	"path/filepath"
	"syscall"

	bpfencoding "github.com/Soil-Security/bpf/encoding"
	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/ringbuf"
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

	decoder := &bpfencoding.Decoder{
		ByteOrder: spec.ByteOrder,
	}

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

				err = parseAndPrintEvent(record.RawSample, decoder)
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

func parseAndPrintEvent(buf []byte, decoder *bpfencoding.Decoder) error {
	e := event{}
	err := e.unpack(buf, decoder)
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

func (e *event) unpack(buf []byte, decoder *bpfencoding.Decoder) error {
	var off = 0
	var err error

	e.Pid, off, err = decoder.Uint32AsInt(buf, off)
	if err != nil {
		return err
	}
	e.PPid, off, err = decoder.Uint32AsInt(buf, off)
	if err != nil {
		return err
	}

	e.Comm, off, err = decoder.Str(buf, off, 16)
	if err != nil {
		return err
	}

	e.Uid, off, err = decoder.Uint32AsInt(buf, off)
	if err != nil {
		return err
	}

	e.retval, off, err = decoder.Uint32AsInt(buf, off)
	if err != nil {
		return err
	}

	e.argsCount, off, err = decoder.Byte(buf, off)
	if err != nil {
		return err
	}

	e.argsSize, off, err = decoder.Uint16AsInt(buf, off)
	if err != nil {
		return err
	}

	e.Args, off, err = decoder.Strs(buf, off, e.argsSize)
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
