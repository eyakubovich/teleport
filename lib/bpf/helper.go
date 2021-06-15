// +build bpf,!386

/*
Copyright 2019 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package bpf

import (
	"github.com/aquasecurity/libbpfgo"
	"github.com/gravitational/trace"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/sirupsen/logrus"

	"github.com/gravitational/teleport"

	"encoding/binary"
	"os"
	"sync"
)

var log = logrus.WithFields(logrus.Fields{
	trace.Component: teleport.ComponentBPF,
})

const (
	kprobeProgPrefix     = "kprobe__"
	kretprobeProgPrefix  = "kretprobe__"
	tracepointProgPrefix = "tracepoint__"
	syscallsCategory     = "syscalls"
	syscallEnterPrefix   = "sys_enter_"
	syscallExitPrefix    = "sys_exit_"
	counterSuffix        = "_counter"
	doorbellSuffix       = "_doorbell"
)

var pageSize = os.Getpagesize()

// ResizeMap resizes (changes max number of entries) the
// map to the specified value. This function must be called
// before BPFLoadObject has been called..
func ResizeMap(mod *libbpfgo.Module, mapName string, value uint32) error {
	m, err := mod.GetMap(mapName)
	if err != nil {
		return trace.Wrap(err)
	}

	if err = m.Resize(value); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// AttachKprobe attaches both a kprobe and kretprobe for the
// function identified by "name". The BPF C functions must be
// called "kprobe__NAME" and "kretprobe__NAME" where NAME
// the name of the kernel function to be hooked.
func AttachKprobe(mod *libbpfgo.Module, name string) error {
	prog, err := mod.GetProgram(kprobeProgPrefix + name)
	if err != nil {
		return trace.Wrap(err)
	}

	_, err = prog.AttachKprobe(name)
	if err != nil {
		return trace.Wrap(err)
	}

	prog, err = mod.GetProgram(kretprobeProgPrefix + name)
	if err != nil {
		return trace.Wrap(err)
	}

	_, err = prog.AttachKretprobe(name)
	if err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// AttachTracepoint attaches a tracepoint identified by category:name.
// The BPF C function must be called "tracepoint__CATEGORY__NAME" where
// CATEGORY and NAME are the tracepoint's category and name.
func AttachTracepoint(mod *libbpfgo.Module, category, name string) error {
	prog, err := mod.GetProgram(tracepointProgPrefix + category + "__" + name)
	if err != nil {
		return trace.Wrap(err)
	}

	_, err = prog.AttachTracepoint(category + ":" + name)
	return err
}

// AttachSyscallTracepoint hooks a syscall using the tracepoint mechanism.
// Like Kprobe, it hooks the entry and exit points. Unlike the Kprobe, it
// is stable and not sensitive to the kernel renaming its functions.
// The BPF C functions must be called "tracepoint__sys_enter__SYSCALL" and
// "tracepoint__sys_exit__SYSCALL" where SYSCALL is the name of the syscalled
// to be hooked.
//
// For more details, see https://www.kernel.org/doc/html/v5.8/trace/events.html.
func AttachSyscallTracepoint(mod *libbpfgo.Module, syscall string) error {
	if err := AttachTracepoint(mod, syscallsCategory, syscallEnterPrefix+syscall); err != nil {
		return trace.Wrap(err)
	}

	if err := AttachTracepoint(mod, syscallsCategory, syscallExitPrefix+syscall); err != nil {
		return trace.Wrap(err)
	}

	return nil
}

// RingBuffer wraps a BPF ring buffer with a channel that will
// receive the data from the ring buffer.
type RingBuffer struct {
	buf     *libbpfgo.RingBuffer
	EventCh chan []byte
}

// NewRingBuffer creates a RingBuffer object identified by "name". The messages
// from the ring buffer will be available on the EventCh channel.
func NewRingBuffer(mod *libbpfgo.Module, name string) (*RingBuffer, error) {
	rb := &RingBuffer{
		EventCh: make(chan []byte, chanSize),
	}

	var err error
	rb.buf, err = mod.InitRingBuf(name, rb.EventCh)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	rb.buf.Start()

	return rb, nil
}

// Close will stop receiving messages from the kernel and putting them
// into EventCh channel.
func (rb *RingBuffer) Close() {
	rb.buf.Stop()
	// don't Close ring buffers as they'll be closed as part of Module.Close()
}

// Counter allows a BPF program to increment a Prometheus counter.
// The counter value is stored in a one element BPF array (map).
// When it's incremented, the BPF program also rings the doorbell
// via a ring buffer.
type Counter struct {
	// doorbelBuf contains dummy bytes and is used for signaling the userspace
	doorbellBuf *libbpfgo.RingBuffer
	// doorbellCh is the chan corresponding to doorbellBuf
	doorbellCh chan []byte

	// arr is a one element array containing the value
	arr *libbpfgo.BPFMap
	// lastCnt keeps the last read counter value
	lastCnt uint64

	// wg is used to wait for the loop goroutine to finish
	wg sync.WaitGroup

	// counter is the associated Prometheous counter to increment
	counter prometheus.Counter
}

// NewLostCounter starts tracking the lost messages and updating the Prometheous counter.
func NewCounter(mod *libbpfgo.Module, name string, counter prometheus.Counter) (*Counter, error) {
	c := &Counter{
		doorbellCh: make(chan []byte, chanSize),
		counter:    counter,
	}

	var err error

	c.arr, err = mod.GetMap(name + counterSuffix)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	c.doorbellBuf, err = mod.InitRingBuf(name+doorbellSuffix, c.doorbellCh)
	if err != nil {
		return nil, trace.Wrap(err)
	}

	c.doorbellBuf.Start()

	c.wg.Add(1)
	go c.loop()

	return c, nil
}

// Close will stop tracking and release the resources.
func (c *Counter) Close() {
	c.doorbellBuf.Stop()
	// don't Close ring buffers as they'll be closed as part of Module.Close()

	// wait for lostLoop to finish
	c.wg.Wait()
}

func (c *Counter) loop() {
	for _ = range c.doorbellCh {
		cntBytes, err := c.arr.GetValue(int32(0), 8)
		if err != nil {
			log.Errorf("Error reading array value at index 0")
			continue
		}

		cnt := binary.LittleEndian.Uint64(cntBytes)
		if delta := cnt - c.lastCnt; delta > 0 {
			c.counter.Add(float64(delta))
		}

		c.lastCnt = cnt
	}

	c.wg.Done()
}

const (
	// commMax is the maximum length of a command from linux/sched.h.
	commMax = 16

	// pathMax is the maximum length of a path from linux/limits.h.
	pathMax = 255

	// argvMax is the maximum length of the args vector.
	argvMax = 128

	// eventArg is an exec event that holds the arguments to a function.
	eventArg = 0

	// eventRet holds the return value and other data about about an event.
	eventRet = 1

	// chanSize is the size of the event channels.
	chanSize = 1024
)
