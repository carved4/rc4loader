package hostinfo

import (
	"fmt"
	"unsafe"
	"github.com/carved4/go-native-syscall"
	"rc4loader/pkg/types"
)


func DemonstrateHostInfoGathering() {
	fmt.Println("[+] host information gathering using query functions")
	

	fmt.Print("[+] querying os version... ")
	var versionInfo types.RTL_OSVERSIONINFOW
	versionInfo.OSVersionInfoSize = uint32(unsafe.Sizeof(versionInfo))
	
	result, err := winapi.CallNtdllFunction("RtlGetVersion", uintptr(unsafe.Pointer(&versionInfo)))
	if err != nil {
		fmt.Printf("failed: %v\n", err)
	} else {
		fmt.Printf("success\n")
		fmt.Printf("[+] windows version: %d.%d.%d\n", versionInfo.MajorVersion, versionInfo.MinorVersion, versionInfo.BuildNumber)
		fmt.Printf("[+] platform id: %d\n", versionInfo.PlatformId)
	}
	
	
	fmt.Print("[+] querying system uptime... ")
	var systemTime types.LARGE_INTEGER
	result, err = winapi.CallNtdllFunction("RtlQueryUnbiasedInterruptTime", uintptr(unsafe.Pointer(&systemTime)))
	if err != nil {
		fmt.Printf("failed: %v\n", err)
	} else {
		fmt.Printf("success\n")
		uptimeMs := uint64(systemTime.LowPart) | uint64(systemTime.HighPart)<<32
		uptimeSeconds := uptimeMs / 10000000 // Convert from 100ns units to seconds
		hours := uptimeSeconds / 3600
		minutes := (uptimeSeconds % 3600) / 60
		seconds := uptimeSeconds % 60
		fmt.Printf("[+] system uptime: %d hours, %d minutes, %d seconds\n", hours, minutes, seconds)
	}
	
	
	fmt.Print("[+] querying time zone information... ")
	timeZoneBuffer := make([]byte, 512)
	result, err = winapi.CallNtdllFunction("RtlQueryTimeZoneInformation", uintptr(unsafe.Pointer(&timeZoneBuffer[0])))
	if err != nil {
		fmt.Printf("failed: %v\n", err)
	} else {
		fmt.Printf("success\n")
		if result == 0 {
			bias := *(*int32)(unsafe.Pointer(&timeZoneBuffer[0]))
			fmt.Printf("[+] time zone bias: %d minutes from UTC\n", bias)
		}
	}
	
	
	fmt.Print("[+] querying process elevation... ")
	var elevationFlags uint32
	result, err = winapi.CallNtdllFunction("RtlQueryElevationFlags", uintptr(unsafe.Pointer(&elevationFlags)))
	if err != nil {
		fmt.Printf("failed: %v\n", err)
	} else {
		fmt.Printf("success\n")
		fmt.Printf("[+] elevation flags raw value: 0x%x\n", elevationFlags)
		
		// More accurate elevation detection - try to adjust a privilege that requires elevation
		fmt.Print("[+] testing actual elevation via privilege adjustment... ")
		const SE_DEBUG_PRIVILEGE = 20
		var previousState uint8
		
		privResult, privErr := winapi.CallNtdllFunction("RtlAdjustPrivilege",
			uintptr(SE_DEBUG_PRIVILEGE),
			uintptr(1), // Enable
			uintptr(0), // Current process
			uintptr(unsafe.Pointer(&previousState)))
		
		if privErr != nil {
			fmt.Printf("failed: %v\n", privErr)
			fmt.Printf("[+] process is likely running non-elevated (standard user)\n")
		} else if privResult == 0 {
			fmt.Printf("success\n")
			fmt.Printf("[+] process is running elevated (admin) - can adjust debug privilege\n")
			
			// Restore previous state
			winapi.CallNtdllFunction("RtlAdjustPrivilege",
				uintptr(SE_DEBUG_PRIVILEGE),
				uintptr(previousState),
				uintptr(0),
				uintptr(unsafe.Pointer(&previousState)))
		} else {
			fmt.Printf("partial success (ntstatus: 0x%x)\n", privResult)
			if privResult == 0xC0000061 { // STATUS_PRIVILEGE_NOT_HELD
				fmt.Printf("[+] process is running non-elevated (standard user) - privilege not held\n")
			} else {
				fmt.Printf("[+] process elevation status unclear (ntstatus: 0x%x)\n", privResult)
			}
		}
	}
	

	fmt.Print("[+] querying module information... ")
	var moduleInfo [256]byte
	result, err = winapi.CallNtdllFunction("RtlQueryModuleInformation",
		uintptr(unsafe.Pointer(&moduleInfo[0])),
		uintptr(len(moduleInfo)),
		uintptr(0)) // ReturnLength
	
	if err != nil {
		fmt.Printf("failed: %v\n", err)
	} else {
		fmt.Printf("success (ntstatus: 0x%x)\n", result)
	}
	

	fmt.Print("[+] querying package identity... ")
	identityBuffer := make([]byte, 512)
	result, err = winapi.CallNtdllFunction("RtlQueryPackageIdentity",
		uintptr(0), // Process handle (0 = current)
		uintptr(unsafe.Pointer(&identityBuffer[0])),
		uintptr(len(identityBuffer)),
		uintptr(0), // ReturnLength
		uintptr(0)) // Reserved
	
	if err != nil {
		fmt.Printf("failed: %v\n", err)
	} else {
		fmt.Printf("success (ntstatus: 0x%x)\n", result)
		if result == 0 {
			fmt.Printf("[+] package identity query successful\n")
		}
	}
	

	fmt.Print("[+] querying protected policy... ")
	policyGuid := types.GUID{Data1: 0x6C2C, Data2: 0x0000, Data3: 0x0000}
	var policyValue uint32
	
	result, err = winapi.CallNtdllFunction("RtlQueryProtectedPolicy",
		uintptr(unsafe.Pointer(&policyGuid)),
		uintptr(unsafe.Pointer(&policyValue)))
	
	if err != nil {
		fmt.Printf("failed: %v\n", err)
	} else {
		fmt.Printf("success\n")
		fmt.Printf("[+] protected policy value: 0x%x (ntstatus: 0x%x)\n", policyValue, result)
	}
	

	fmt.Println("[+] querying critical system environment variables...")
	
	envVars := []struct{
		name string
		bufferSize int
		description string
	}{
		{"COMPUTERNAME", 256, "computer name"},
		{"USERNAME", 256, "current user"}, 
		{"USERDOMAIN", 256, "user domain"},
		{"USERDNSDOMAIN", 256, "dns domain name"},
		{"LOGONSERVER", 256, "logon server"},
		{"SESSIONNAME", 128, "session type"},
		{"CLIENTNAME", 256, "rdp client name"},
		{"OS", 256, "operating system"},
		{"PROCESSOR_ARCHITECTURE", 256, "cpu architecture"},
		{"PROCESSOR_LEVEL", 64, "processor level"},
		{"PROCESSOR_REVISION", 64, "processor revision"},
		{"PROCESSOR_IDENTIFIER", 512, "processor model"},
		{"NUMBER_OF_PROCESSORS", 64, "cpu count"},
		{"COMSPEC", 512, "command shell"},
		{"PATHEXT", 256, "executable extensions"},
		{"HOMEDRIVE", 32, "home drive letter"},
		{"SYSTEMROOT", 512, "windows directory"},
	}
	
	for _, envVar := range envVars {
		fmt.Printf("[+] %s (%s)... ", envVar.description, envVar.name)
		envVarWide := types.CreateWideString(envVar.name)
		envVarUnicode := types.UNICODE_STRING{
			Length:        uint16((len(envVarWide) - 1) * 2),
			MaximumLength: uint16(len(envVarWide) * 2),
			Buffer:        &envVarWide[0],
		}
		
		resultBuffer := make([]uint16, envVar.bufferSize)
		resultUnicode := types.UNICODE_STRING{
			Length:        0,
			MaximumLength: uint16(len(resultBuffer) * 2),
			Buffer:        &resultBuffer[0],
		}
		
		result, err := winapi.CallNtdllFunction("RtlQueryEnvironmentVariable_U",
			uintptr(0),
			uintptr(unsafe.Pointer(&envVarUnicode)),
			uintptr(unsafe.Pointer(&resultUnicode)))
		
		if err != nil {
			fmt.Printf("failed: %v\n", err)
		} else if result == 0 {
			resultLen := int(resultUnicode.Length / 2)
			resultStr := ""
			for i := 0; i < resultLen && i < len(resultBuffer); i++ {
				if resultBuffer[i] == 0 {
					break
				}
				resultStr += string(rune(resultBuffer[i]))
			}
			fmt.Printf("success\n")
			fmt.Printf("[+] %s\n", resultStr)
		} else {
			fmt.Printf("failed (ntstatus: 0x%x)\n", result)
		}
	}
	
	fmt.Println()
}