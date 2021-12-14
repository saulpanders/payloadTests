# payloadTests
PoCs for various shellcode injection techniques. Mostly golang.

this repo is mostly for my own educational purposes, so I wouldn't consider these opsec-safe. ymmv

currently using package "golang.org/x/sys/windows" for some WinAPI stuff

shellcode in buffer pops calc.exe

## Techniques

A lot of these examples follow the classic "Allocate-Inject-Execute" pattern. Some target the current process's execution space, while other abuse a remote process.

### CreateFiber

### CreateRemoteThread


### Process Hollowing (64-bit)

### QueueUserApc

### RtlCreateUserThread


