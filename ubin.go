package main

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"log"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
)

const (
	magicHeader1 = 0x42
	magicHeader2 = 0x4E
	nullByte     = 0x00
)

var expectedSignature = []byte{0x3A, 0x94, 0x71, 0xDA}

func runubin(fileData []byte) {
	if len(fileData) < 19 {
		log.Fatalf("Error: Invalid .ubin file: File is too small.")
	}

	if fileData[0] != magicHeader1 || fileData[1] != magicHeader2 || fileData[2] != nullByte {
		log.Fatalf("Error: Invalid .ubin magic header bytes.")
	}

	if !bytes.Equal(fileData[3:7], expectedSignature) {
		log.Fatalf("Error: Invalid .ubin signature.")
	}

	offset := 7

	winLen := binary.LittleEndian.Uint32(fileData[offset : offset+4])
	offset += 4
	winCode := fileData[offset : offset+int(winLen)]
	offset += int(winLen)

	macLen := binary.LittleEndian.Uint32(fileData[offset : offset+4])
	offset += 4
	macCode := fileData[offset : offset+int(macLen)]
	offset += int(macLen)

	linuxLen := binary.LittleEndian.Uint32(fileData[offset : offset+4])
	offset += 4
	linuxCode := fileData[offset : offset+int(linuxLen)]
	offset += int(linuxLen)

	footer := fileData[len(fileData)-2:]
	validStandard := (footer[0] == 0x6C && footer[1] == 0x0E)
	validExtra := (footer[0] == 0x2F && footer[1] == 0x8A)

	if !validStandard && !validExtra {
		log.Fatalf("Error: Invalid storage option footer.")
	}

	var targetCode []byte
	var targetDir string
	fileExt := ""

	switch runtime.GOOS {
	case "windows":
		targetCode = winCode
		targetDir = os.Getenv("TEMP")
		if targetDir == "" {
			targetDir = os.TempDir()
		}
		fileExt = ".exe"
	case "darwin":
		targetCode = macCode
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Error getting user home directory: %v", err)
		}
		targetDir = filepath.Join(home, "Library", "Caches")
	case "linux":
		targetCode = linuxCode
		targetDir = "/tmp"
	default:
		log.Fatalf("Error: Unsupported operating system: %s", runtime.GOOS)
	}

	if len(targetCode) == 0 {
		log.Fatalf("Error: No binary embedded in this .ubin container for OS: %s", runtime.GOOS)
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		log.Fatalf("Error creating target directory: %v", err)
	}

	tmpFile, err := os.CreateTemp(targetDir, "ubin-*"+fileExt)
	if err != nil {
		log.Fatalf("Error creating temporary file: %v", err)
	}
	tmpPath := tmpFile.Name()
	tmpFile.Close()
	defer os.Remove(tmpPath)

	if validExtra {
		extraStart := offset
		extraEnd := len(fileData) - 2
		if extraStart < extraEnd {
			extraBytes := fileData[extraStart:extraEnd]
			txtPath := tmpPath + ".txt"
			defer os.Remove(txtPath)
			_ = os.WriteFile(txtPath, extraBytes, 0644)
		}
	}

	err = os.WriteFile(tmpPath, targetCode, 0755)
	if err != nil {
		log.Fatalf("Error writing temporary executable: %v", err)
	}

	cmd := exec.Command(tmpPath)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin

	err = cmd.Run()
	if err != nil {
		log.Fatalf("Execution failed: %v", err)
	}
}

func main() {
	args := os.Args[1:]
	if len(args) == 0 {
		log.Fatalf("Error: No arguments provided.")
	}

	isCompiler := false
	var binaries []string
	extraBytesPath := ""
	outputPath := "output.ubin"

	for i := 0; i < len(args); i++ {
		switch args[i] {
		case "--compiler":
			isCompiler = true
			// Collect the next 3 arguments strictly as binary paths
			for j := 0; j < 3; j++ {
				if i+1 < len(args) {
					binaries = append(binaries, args[i+1])
					i++
				}
			}
		case "--extrabytes":
			if i+1 < len(args) {
				extraBytesPath = args[i+1]
				i++
			}
		case "-o":
			if i+1 < len(args) {
				outputPath = args[i+1]
				i++
			}
		default:
			if !isCompiler {
				binaries = append(binaries, args[i])
			}
		}
	}

	if isCompiler {
		if len(binaries) < 3 {
			log.Fatalf("Error: --compiler requires exactly 3 binary paths: <winbin> <macbin> <linuxbin>")
		}

		winBytes, err := os.ReadFile(binaries[0])
		if err != nil {
			log.Fatalf("Error reading Windows binary (%s): %v", binaries[0], err)
		}
		macBytes, err := os.ReadFile(binaries[1])
		if err != nil {
			log.Fatalf("Error reading macOS binary (%s): %v", binaries[1], err)
		}
		linuxBytes, err := os.ReadFile(binaries[2])
		if err != nil {
			log.Fatalf("Error reading Linux binary (%s): %v", binaries[2], err)
		}

		var extra []byte
		footer := []byte{0x6C, 0x0E}

		if extraBytesPath != "" {
			extra, err = os.ReadFile(extraBytesPath)
			if err != nil {
				log.Fatalf("Error reading extra bytes file: %v", err)
			}
			if len(extra) > 512 {
				log.Fatalf("Error: Extra bytes exceed 512-byte limit.")
			}
			footer = []byte{0x2F, 0x8A}
		}

		var buffer bytes.Buffer
		buffer.Write([]byte{magicHeader1, magicHeader2, nullByte})
		buffer.Write(expectedSignature)

		lenBytes := make([]byte, 4)

		binary.LittleEndian.PutUint32(lenBytes, uint32(len(winBytes)))
		buffer.Write(lenBytes)
		buffer.Write(winBytes)

		binary.LittleEndian.PutUint32(lenBytes, uint32(len(macBytes)))
		buffer.Write(lenBytes)
		buffer.Write(macBytes)

		binary.LittleEndian.PutUint32(lenBytes, uint32(len(linuxBytes)))
		buffer.Write(lenBytes)
		buffer.Write(linuxBytes)

		if len(extra) > 0 {
			buffer.Write(extra)
		}
		buffer.Write(footer)

		err = os.WriteFile(outputPath, buffer.Bytes(), 0644)
		if err != nil {
			log.Fatalf("Error writing output file: %v", err)
		}
		fmt.Printf("Successfully compiled multi-platform container to %s\n", outputPath)
		return
	}

	if len(binaries) == 0 {
		log.Fatalf("Error: No .ubin file specified for execution.")
	}

	targetFile := binaries[0]
	fileData, err := os.ReadFile(targetFile)
	if err != nil {
		log.Fatalf("Error reading target file: %v", err)
	}

	if len(fileData) == 0 {
		log.Fatalf("Error: Target file is empty.")
	}

	runubin(fileData)
}
