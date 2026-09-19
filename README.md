# Installation

Install with:

pip install -r requirements.txt

```
pip install pefile dnfile lief capstone pycryptodome reportlab pdfplumber python-certutil
pip install pefile dnfile capstone reportlab
```

Notes on libraries used:

- **pefile** — PE header, sections, imports/exports, resources
- **dnfile** — .NET metadata detection
- **lief** — robust PE parsing fallback + signature info
- **capstone** — disassembly at the entry point (architecture-aware)
- **reportlab** — PDF report generation (pure Python, no external binaries)
- **Digital signature** — uses Windows WinVerifyTrust via ctypes when on Windows, plus a manual Authenticode parse of the SECURITY directory (works on any OS).

## Usage

```
# Full analysis - generates all 4 report formats + extracted files
python pe_analyze.py suspicious.exe

# Custom output directory
python pe_analyze.py malware.exe -o ./analysis_output

# Quiet mode (just the summary)
python pe_analyze.py malware.exe -q
```

Example output structure:

```
sample_analysis/
├── report.json        # Full machine-readable results
├── report.txt         # Human-readable text report
├── report.html        # Dark-themed interactive HTML report
├── report.pdf         # Formatted PDF report
├── resources/         # Extracted icons, bitmaps, manifests, versions...
│   └── rt3_1_1033.ico
├── embedded/          # Discovered embedded blobs
│   ├── embedded_cab_54212.cab
│   ├── embedded_zip_88231.zip
│   ├── embedded_pe_120000.exe
│   └── extracted/     # CAB/ZIP payloads unpacked here
└── ...
```

## Feature notes

| Feature | How it works |
|---|---|
| Arch/type detection | Machine field + OptionalHeader magic (PE32/PE32+), Mach-O/ELF magic fallback |
| PE headers | Full DOS/FILE/OPTIONAL header dump, data directories, checksum validation |
| CAB extraction | Parses MSCF CFHEADER cbCabinet field for exact blob size, then cabextract/7z |
| Digital signature | Reads IMAGE_DIRECTORY_ENTRY_SECURITY (Authenticode WIN_CERTIFICATE), parses PKCS#7 certificates via cryptography, and runs WinVerifyTrust on Windows for full chain/trust validation |
| Embedded files | Magic scanning for ZIP/RAR/7z/CAB/PE/GZIP/PDF/etc., with extent calculation (EOCD for ZIP, section table for nested PE), plus archive unpacking |
| Packer detection | Section-name signatures (UPX, VMProtect, Themida, ASPack, MPRESS...), entropy > 7.2, overlay size heuristics |
| Strings | ASCII + UTF-16LE extraction with IOC extraction: URLs, IPs, emails, registry keys, file paths, suspicious API/keyword list |
| Resources | Recursive resource tree walk, saved by type (icons, bitmaps, manifests, version info parsed) |
| Imports/Exports | Per-DLL function lists with ordinals/addresses; export table with DLL name |
| .NET | dnfile metadata: assembly name, version, types, managed resources |
| Disassembly | Capstone at entry point, architecture-aware (x86/x64/ARM/ARM64) |
