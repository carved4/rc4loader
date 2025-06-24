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

## usage

```bash
# show help
go run cmd/main.go -help

# run demo mode (embedded messagebox)
go run cmd/main.go -demo

# download and execute shellcode from url
go run cmd/main.go -url <url>
```

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

## author

me 