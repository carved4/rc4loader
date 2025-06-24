package process

import (
	"fmt"
	"sort"
	"strings"
	"unsafe"
	
	winapi "github.com/carved4/go-native-syscall"
)

type ProcessInfo struct {
	Pid  uint32
	Name string
}

// isSystemProcess checks if a process should be filtered out as a system process
func isSystemProcess(pid uint32, name string) bool {
	// Filter out system PIDs
	if pid <= 4 {
		return true
	}
	
	// Convert to lowercase for comparison
	lowerName := strings.ToLower(name)
	
	// Filter out core Windows system processes
	systemProcesses := []string{
		"system",
		"system idle process",
		"smss.exe",
		"csrss.exe", 
		"wininit.exe",
		"winlogon.exe",
		"services.exe",
		"lsass.exe",
		"svchost.exe",
		"spoolsv.exe",
		"dwm.exe",
		"explorer.exe", // Optional: you might want to keep this for some scenarios
		"taskhostw.exe",
		"sihost.exe",
		"ctfmon.exe",
		"conhost.exe",
		"dllhost.exe",
		"runtimebroker.exe",
		"searchindexer.exe",
		"searchprotocolhost.exe",
		"audiodg.exe",
		"fontdrvhost.exe",
		"secure system",
		"registry",
		"memory compression",
		"antimalware service executable",
		"windows security health service",
		"wuauclt.exe",
		"taskmgr.exe",
		"mmc.exe",
		"winver.exe",
		"perfmon.exe",
		"eventlog.exe",
		"logonui.exe",
		"userinit.exe",
		"networkservice",
		"localservice",
		"dllhost.exe",
		"wbem",
		"wmi",
	}
	
	// Check if process name matches any system process
	for _, sysProc := range systemProcesses {
		if strings.Contains(lowerName, sysProc) {
			return true
		}
	}
	
	// Filter out processes with common system prefixes
	systemPrefixes := []string{
		"nt ",
		"kernel",
		"interrupt",
		"dpc",
		"idle",
		"system",
	}
	
	for _, prefix := range systemPrefixes {
		if strings.HasPrefix(lowerName, prefix) {
			return true
		}
	}
	
	return false
}

func utf16ToString(ptr *uint16, maxLen int) string {
	if ptr == nil {
		return ""
	}
	
	var result []uint16
	for i := 0; i < maxLen; i++ {
		char := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i)*2))
		if char == 0 {
			break
		}
		result = append(result, char)
	}
	
	// Simple conversion for ASCII characters
	var str strings.Builder
	for _, char := range result {
		if char < 128 {
			str.WriteByte(byte(char))
		} else {
			str.WriteRune('?') // Replace non-ASCII with ?
		}
	}
	return str.String()
}

func GetProcessList() ([]ProcessInfo, error) {
	// First call to get required buffer size
	var returnLength uintptr
	status, err := winapi.NtQuerySystemInformation(
		winapi.SystemProcessInformation,
		nil,
		0,
		&returnLength,
	)
	
	if status != winapi.STATUS_INFO_LENGTH_MISMATCH && status != winapi.STATUS_BUFFER_TOO_SMALL {
		return nil, fmt.Errorf("failed to get buffer size: %s", winapi.FormatNTStatus(status))
	}
	
	// Allocate buffer with some extra space
	bufferSize := returnLength + 4096
	buffer := make([]byte, bufferSize)
	
	// Second call to get actual data
	status, err = winapi.NtQuerySystemInformation(
		winapi.SystemProcessInformation,
		unsafe.Pointer(&buffer[0]),
		bufferSize,
		&returnLength,
	)
	
	if err != nil {
		return nil, fmt.Errorf("NtQuerySystemInformation error: %v", err)
	}
	
	if status != winapi.STATUS_SUCCESS {
		return nil, fmt.Errorf("NtQuerySystemInformation failed: %s", winapi.FormatNTStatus(status))
	}
	
	var processes []ProcessInfo
	offset := uintptr(0)
	processCount := 0
	
	for {
		// Safety check to prevent buffer overflow
		if offset >= uintptr(len(buffer)) {
			break
		}
		
		// Get current process entry
		processInfo := (*winapi.SYSTEM_PROCESS_INFORMATION)(unsafe.Pointer(&buffer[offset]))
		processCount++
		
		// Extract process name from UNICODE_STRING
		var processName string
		if processInfo.ImageName.Buffer != nil && processInfo.ImageName.Length > 0 {
			maxChars := int(processInfo.ImageName.Length / 2) // Length is in bytes, convert to chars
			if maxChars > 260 { // MAX_PATH protection
				maxChars = 260
			}
			processName = utf16ToString(processInfo.ImageName.Buffer, maxChars)
		} else {
			// Handle System Idle Process (PID 0) which has no name
			if processInfo.UniqueProcessId == 0 {
				processName = "System Idle Process"
			} else {
				processName = fmt.Sprintf("Process_%d", processInfo.UniqueProcessId)
			}
		}
		
		// Skip System Idle Process (PID 0) and system processes
		if processInfo.UniqueProcessId != 0 && processName != "" && !isSystemProcess(uint32(processInfo.UniqueProcessId), processName) {
			// Check if we can open the process with injection-level permissions
			if canOpenProcessForInjection(uint32(processInfo.UniqueProcessId)) {
				processes = append(processes, ProcessInfo{
					Pid:  uint32(processInfo.UniqueProcessId),
					Name: processName,
				})
			}
		}
		
		// Move to next entry
		if processInfo.NextEntryOffset == 0 {
			break
		}
		offset += uintptr(processInfo.NextEntryOffset)
	}
	
	// Sort processes by name for easier readability
	sort.Slice(processes, func(i, j int) bool {
		return processes[i].Name < processes[j].Name
	})
	
	return processes, nil
}

// isProcessRunning checks if a process is still running using NtQueryInformationProcess
func isProcessRunning(pid uint32) error {
	// Open the process
	var processHandle uintptr
	clientId := winapi.CLIENT_ID{
		UniqueProcess: uintptr(pid),
		UniqueThread:  0,
	}
	
	// Initialize OBJECT_ATTRIBUTES properly
	objAttrs := winapi.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
	}
	
	status, err := winapi.NtOpenProcess(
		&processHandle,
		winapi.PROCESS_QUERY_LIMITED_INFORMATION,
		uintptr(unsafe.Pointer(&objAttrs)),
		uintptr(unsafe.Pointer(&clientId)),
	)
	
	if err != nil {
		return fmt.Errorf("failed to open process for verification: %v", err)
	}
	
	if status != winapi.STATUS_SUCCESS {
		return fmt.Errorf("failed to open process: %s", winapi.FormatNTStatus(status))
	}
	
	defer winapi.NtClose(processHandle)
	
	// Query basic process information
	var processInfo winapi.PROCESS_BASIC_INFORMATION
	var returnLength uintptr
	
	status, err = winapi.NtQueryInformationProcess(
		processHandle,
		winapi.ProcessBasicInformation,
		unsafe.Pointer(&processInfo),
		unsafe.Sizeof(processInfo),
		&returnLength,
	)
	
	if err != nil {
		return fmt.Errorf("failed to query process information: %v", err)
	}
	
	if status != winapi.STATUS_SUCCESS {
		return fmt.Errorf("process query failed: %s", winapi.FormatNTStatus(status))
	}
	
	// If we can query the process, it's running
	// The ExitStatus would be non-zero if the process had exited
	return nil
}

// canOpenProcessForInjection checks if we can open a process with the permissions needed for injection
func canOpenProcessForInjection(pid uint32) bool {
	var processHandle uintptr
	clientId := winapi.CLIENT_ID{
		UniqueProcess: uintptr(pid),
		UniqueThread:  0,
	}
	
	// Initialize OBJECT_ATTRIBUTES
	objAttrs := winapi.OBJECT_ATTRIBUTES{
		Length: uint32(unsafe.Sizeof(winapi.OBJECT_ATTRIBUTES{})),
	}
	
	// Try to open with the exact permissions we need for injection:
	// PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_CREATE_THREAD | PROCESS_QUERY_INFORMATION
	requiredAccess := winapi.PROCESS_VM_OPERATION | winapi.PROCESS_VM_WRITE | winapi.PROCESS_CREATE_THREAD | winapi.PROCESS_QUERY_INFORMATION
	
	status, err := winapi.NtOpenProcess(
		&processHandle,
		uintptr(requiredAccess),
		uintptr(unsafe.Pointer(&objAttrs)),
		uintptr(unsafe.Pointer(&clientId)),
	)
	
	if err != nil || status != winapi.STATUS_SUCCESS {
		// If specific permissions fail, try with PROCESS_ALL_ACCESS (what injection actually uses)
		status, err = winapi.NtOpenProcess(
			&processHandle,
			uintptr(winapi.PROCESS_ALL_ACCESS),
			uintptr(unsafe.Pointer(&objAttrs)),
			uintptr(unsafe.Pointer(&clientId)),
		)
		
		if err != nil || status != winapi.STATUS_SUCCESS {
			return false
		}
	}
	
	// Successfully opened, now check if process is actually accessible
	defer winapi.NtClose(processHandle)
	
	// Try to query basic process information to verify we have real access
	var processInfo winapi.PROCESS_BASIC_INFORMATION
	var returnLength uintptr
	
	status, err = winapi.NtQueryInformationProcess(
		processHandle,
		winapi.ProcessBasicInformation,
		unsafe.Pointer(&processInfo),
		unsafe.Sizeof(processInfo),
		&returnLength,
	)
	
	if err != nil || status != winapi.STATUS_SUCCESS {
		return false
	}
	
	// Additional check: try to check if process is still running and accessible
	// A process that's terminating or protected might open but not be injectable
	if processInfo.ExitStatus != 0x00000103 { // STILL_ACTIVE
		return false
	}
	
	return true
}


