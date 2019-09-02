/* Benchmark the latency involved when talking to another HTTP service on the same machine.
This is part of an investigation into the costs of inter-service authentication.
*/
package main

import (
	"bytes"
	"fmt"
	"net/http"
	"os/exec"
	"syscall"
	"time"
	"unsafe"
)

var kernel32 *syscall.DLL
var kernel32_qpf *syscall.Proc
var kernel32_qpc *syscall.Proc

func main() {
	bootWindows()

	freq := float64(QueryPerformanceFrequency())

	cmd := exec.Command("bin/imqsauth.exe", "-c=c:/imqsbin/conf/imqsauth.json", "run")
	var stdout bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Start()
	fmt.Printf("stdout: %v\n", stdout.String())

	min := 10000.0
	max := 0.0
	sum := 0.0
	nsamples := 0.0

	client := &http.Client{}

	fmt.Printf("                        avg min max (microseconds)\n")

	for {
		if nsamples > 2000 {
			nsamples = 0
			sum = 0
			min = 1000000
			max = 0
		}
		start := QueryPerformanceCounter()
		//resp, err := http.Get("http://127.0.0.1:2003/hello")
		resp, err := client.Get("http://127.0.0.1:2003/hello")
		duration := float64(QueryPerformanceCounter()-start) / freq
		if duration < min {
			min = duration
		}
		if duration > max {
			max = duration
		}
		nsamples++
		sum += duration
		micro := 1000.0 * 1000.0
		//fmt.Printf("%v\n", err)
		//fmt.Printf("%v, %v %.0f %.0f %.0f\n", err, resp.Status, sum/nsamples*micro, min*micro, max*micro)
		if int(nsamples)%300 == 0 {
			fmt.Printf("%v, %v %.0f %.0f %.0f %v\n", err, resp.Status, sum/nsamples*micro, min*micro, max*micro, nsamples)
		}
		if err == nil {
			resp.Body.Close()
		}
		time.Sleep(2 * time.Millisecond)
	}

	cmd.Process.Kill()
}

func bootWindows() {
	var err error
	kernel32, err = syscall.LoadDLL("kernel32.dll")
	if err != nil {
		panic(err)
	}

	kernel32_qpc, err = kernel32.FindProc("QueryPerformanceCounter")
	if err != nil {
		panic(err)
	}

	kernel32_qpf, err = kernel32.FindProc("QueryPerformanceFrequency")
	if err != nil {
		panic(err)
	}
}

func QueryPerformanceCounter() int64 {
	var ctr int64
	kernel32_qpc.Call(uintptr(unsafe.Pointer(&ctr)))
	return ctr
}

func QueryPerformanceFrequency() int64 {
	var freq int64
	kernel32_qpf.Call(uintptr(unsafe.Pointer(&freq)))
	return freq
}
