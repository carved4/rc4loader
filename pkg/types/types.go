package types

import (
	"unsafe"
)


type UNICODE_STRING struct {
	Length        uint16
	MaximumLength uint16
	Buffer        *uint16
}

type RTL_OSVERSIONINFOW struct {
	OSVersionInfoSize uint32
	MajorVersion      uint32
	MinorVersion      uint32
	BuildNumber       uint32
	PlatformId        uint32
	CSDVersion        [128]uint16
}

type GUID struct {
	Data1 uint32
	Data2 uint16
	Data3 uint16
	Data4 [8]byte
}


type LARGE_INTEGER struct {
	LowPart  uint32
	HighPart int32
}


func CreateWideString(s string) []uint16 {
	wide := make([]uint16, len(s)+1)
	for i, r := range s {
		wide[i] = uint16(r)
	}
	wide[len(s)] = 0
	return wide
}

func ReadWideString(ptr *uint16, maxLen int) string {
	if ptr == nil {
		return ""
	}
	
	result := ""
	for i := 0; i < maxLen; i++ {
		char := *(*uint16)(unsafe.Pointer(uintptr(unsafe.Pointer(ptr)) + uintptr(i*2)))
		if char == 0 {
			break
		}
		result += string(rune(char))
	}
	return result
}

func CreateUnicodeString(s string) (UNICODE_STRING, []uint16) {
	wide := CreateWideString(s)
	return UNICODE_STRING{
		Length:        uint16(len(s) * 2),
		MaximumLength: uint16(len(wide) * 2),
		Buffer:        &wide[0],
	}, wide
} 