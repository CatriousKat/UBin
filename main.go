package main

import (
	"bytes"
	"encoding/binary"
	"flag"
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
	if len(fileData) < 13 {
		log.Fatalf("Error: Invalid .ubin file: File is too small.")
	}

	if fileData[0] != magicHeader1 || fileData[1] != magicHeader2 || fileData[2] != nullByte {
		log.Fatalf("Error: Invalid .ubin magic header bytes.")
	}

	if !bytes.Equal(fileData[3:7], expectedSignature) {
		log.Fatalf("Error: Invalid .ubin signature.")
	}

	payloadLen := binary.LittleEndian.Uint32(fileData[7:11])
	if uint64(11)+uint64(payloadLen)+uint64(2) > uint64(len(fileData)) {
		log.Fatalf("Error: Malformed .ubin file: Payload length exceeds available file size.")
	}

	execCode := fileData[11 : 11+payloadLen]
	footer := fileData[len(fileData)-2:]

	validStandard := (footer[0] == 0x6C && footer[1] == 0x0E)
	validExtra := (footer[0] == 0x2F && footer[1] == 0x8A)

	if !validStandard && !validExtra {
		log.Fatalf("Error: Invalid storage option footer.")
	}

	var targetDir string
	fileExt := ""

	switch runtime.GOOS {
	case "windows":
		targetDir = os.Getenv("TEMP")
		if targetDir == "" {
			targetDir = os.TempDir()
		}
		fileExt = ".exe"
	case "linux":
		targetDir = "/tmp"
	case "darwin":
		home, err := os.UserHomeDir()
		if err != nil {
			log.Fatalf("Error getting user home directory: %v", err)
		}
		targetDir = filepath.Join(home, "Library", "Caches")
	default:
		log.Fatalf("Error: Unsupported operating system: %s", runtime.GOOS)
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
		extraStart := 11 + int(payloadLen)
		extraEnd := len(fileData) - 2
		if extraStart < extraEnd {
			extraBytes := fileData[extraStart:extraEnd]
			txtPath := tmpPath + ".txt"
			defer os.Remove(txtPath)
			_ = os.WriteFile(txtPath, extraBytes, 0644)
		}
	}

	err = os.WriteFile(tmpPath, execCode, 0755)
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
	compilerPtr := flag.String("compiler", "", "Path to binary file")
	extraBytesPtr := flag.String("extrabytes", "", "Path to extra bytes file")
	getExtraPtr := flag.String("getextra", "", "Path to .ubin file to extract extra bytes from")
	outputPtr := flag.String("o", "output.ubin", "Output file path")

	flag.Parse()

	if *getExtraPtr != "" {
		fileData, err := os.ReadFile(*getExtraPtr)
		if err != nil {
			log.Fatalf("Error reading file: %v", err)
		}
		if len(fileData) < 15 {
			log.Fatalf("Error: File is too small.")
		}

		footer := fileData[len(fileData)-2:]
		if footer[0] != 0x2F || footer[1] != 0x8A {
			log.Fatalf("Error: .ubin file does not contain extra bytes.")
		}

		payloadLen := binary.LittleEndian.Uint32(fileData[7:11])
		extraStart := 11 + int(payloadLen)
		extraEnd := len(fileData) - 2

		if extraStart >= extraEnd {
			log.Fatalf("Error: Malformed extra bytes section.")
		}

		err = os.WriteFile(*outputPtr, fileData[extraStart:extraEnd], 0644)
		if err != nil {
			log.Fatalf("Error writing extracted extra bytes: %v", err)
		}
		return
	}

	if *compilerPtr != "" {
		if _, err := os.Stat(*compilerPtr); os.IsNotExist(err) {
			log.Fatalf("Error: Source file does not exist.")
		}

		code, err := os.ReadFile(*compilerPtr)
		if err != nil {
			log.Fatalf("Error reading source file: %v", err)
		}

		var extra []byte
		footer := []byte{0x6C, 0x0E}

		if *extraBytesPtr != "" {
			extra, err = os.ReadFile(*extraBytesPtr)
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
		binary.LittleEndian.PutUint32(lenBytes, uint32(len(code)))
		buffer.Write(lenBytes)

		buffer.Write(code)
		if len(extra) > 0 {
			buffer.Write(extra)
		}
		buffer.Write(footer)

		err = os.WriteFile(*outputPtr, buffer.Bytes(), 0644)
		if err != nil {
			log.Fatalf("Error writing output file: %v", err)
		}
		return
	}

	args := flag.Args()
	if len(args) < 1 {
		log.Fatalf("Error: No .ubin file specified for execution.")
	}

	targetFile := args[0]
	fileData, err := os.ReadFile(targetFile)
	if err != nil {
		log.Fatalf("Error reading target file: %v", err)
	}

	if len(fileData) == 0 {
		log.Fatalf("Error: Target file is empty.")
	}

	runubin(fileData)
}