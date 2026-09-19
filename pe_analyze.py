#!/usr/bin/env python3
"""
PE Decompiler / Analyzer
- Extracts embedded files (overlay, CAB, ZIP, MSI, self-extractors)
- Identifies file type & architecture
- PE header analysis
- CAB extraction
- Digital signature information / signing check (Authenticode + WinVerifyTrust)
- String extraction
- Resource extraction
- Import / Export analysis
- Reports: HTML, JSON, TXT, PDF

Author: authorized security assessment tooling
"""

import os
import re
import sys
import json
import struct
import hashlib
import datetime
import tempfile
import shutil
import traceback
from io import BytesIO

import pefile
import capstone

# Optional imports with graceful fallback
try:
    import dnfile
    HAS_DNFILE = True
except ImportError:
    HAS_DNFILE = False

try:
    import lief
    lief.logging.disable()
    HAS_LIEF = True
except ImportError:
    HAS_LIEF = False

try:
    from reportlab.lib.pagesizes import letter
    from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
    from reportlab.lib.units import inch
    from reportlab.platypus import (SimpleDocTemplate, Paragraph, Spacer,
                                    Table, TableStyle, PageBreak)
    from reportlab.lib import colors
    HAS_REPORTLAB = True
except ImportError:
    HAS_REPORTLAB = False


# ============================================================
# Constants
# ============================================================

MAGIC_EXES = {
    b'MZ': 'PE executable (DOS/Windows)',
    b'\x7fELF': 'ELF executable (Linux/Unix)',
    b'\xcf\xfa\xed\xfe': 'Mach-O (32-bit, macOS)',
    b'\xca\xfe\xba\xbe': 'Mach-O universal / Java class',
    b'\xfe\xed\xfa\xce': 'Mach-O (32-bit big-endian)',
    b'\xfe\xed\xfa\xcf': 'Mach-O (64-bit big-endian)',
    b'\xcf\xfa\xfa\xce': 'Mach-O (arm)',
}

EMBEDDED_MAGICS = [
    (b'PK\x03\x04',      'zip',       0,      None),
    (b'PK\x05\x06',      'zip_empty', 0,      None),
    (b'Rar!\x1a\x07',    'rar',       0,      None),
    (b'7z\xbc\xaf\x27\x1c', '7z',     0,      None),
    (b'MSCF',            'cab',       0,      None),
    (b'GIF8',            'gif',       0,      None),
    (b'\x89PNG\r\n\x1a\n', 'png',     0,      None),
    (b'\xff\xd8\xff',    'jpeg',      0,      None),
    (b'%PDF',            'pdf',       0,      None),
    (b'ID3',             'mp3',       0,      None),
    (b'RIFF',            'riff',      0,      None),
    (b'BM',              'bmp',       0,      None),
    (b'Ole10Native',     'ole',       0,      None),
    (b'\xd0\xcf\x11\xe0\xa1\xb1\x1a\xe1', 'ole_cfb', 0, None),
    (b'ISc(',            'installshield_cab', 0, None),
    (b'MZ',              'embedded_pe', 0,   None),
    (b'\x1f\x8b',        'gzip',      0,      None),
    (b'BZh',             'bzip2',     0,      None),
    (b'\xfd7zXZ\x00',    'xz',        0,      None),
    (b'\x28\xb5\x2f\xfd','zstd',      0,      None),
    (b'ustar',           'tar',       257,    None),
]

SUBSYSTEMS = {
    1: 'NATIVE', 2: 'WINDOWS_GUI', 3: 'WINDOWS_CUI', 5: 'OS2_CUI',
    7: 'POSIX_CUI', 9: 'WINDOWS_CE_GUI', 10: 'EFI_APPLICATION',
    11: 'EFI_BOOT_SERVICE_DRIVER', 12: 'EFI_RUNTIME_DRIVER',
    13: 'EFI_ROM', 14: 'XBOX', 16: 'WINDOWS_BOOT_APPLICATION',
}

MACHINE_TYPES = {
    0x014c: 'x86 (i386)', 0x8664: 'x64 (AMD64)', 0x01c0: 'ARM',
    0xaa64: 'ARM64', 0x01c4: 'ARMNT', 0x0200: 'IA64 (Itanium)',
    0x5032: 'RISC-V 32', 0x5064: 'RISC-V 64', 0x014d: 'Unknown x86',
    0x0ebc: 'EFI byte code', 0x0266: 'MIPS16', 0x0166: 'MIPS',
}

CHARACTERISTICS = {
    0x0001: 'RELOCS_STRIPPED', 0x0002: 'EXECUTABLE_IMAGE',
    0x0004: 'LINE_NUMS_STRIPPED', 0x0008: 'LOCAL_SYMS_STRIPPED',
    0x0020: 'LARGE_ADDRESS_AWARE', 0x0040: '16BIT (legacy)',
    0x0100: '32BIT_MACHINE', 0x0200: 'DEBUG_STRIPPED',
    0x0400: 'REMOVABLE_RUN_FROM_SWAP', 0x0800: 'NET_RUN_FROM_SWAP',
    0x1000: 'SYSTEM', 0x2000: 'DLL', 0x4000: 'UP_SYSTEM_ONLY',
    0x8000: 'BYTES_REVERSED_HI',
}

SECTION_FLAGS = {
    0x00000020: 'CODE', 0x00000040: 'INITIALIZED_DATA',
    0x00000080: 'UNINITIALIZED_DATA', 0x02000000: 'DISCARDABLE',
    0x04000000: 'NOT_CACHED', 0x08000000: 'NOT_PAGED',
    0x10000000: 'SHARED', 0x20000000: 'EXECUTE', 0x40000000: 'READ',
    0x80000000: 'WRITE',
}

DLL_CHARACTERISTICS = {
    0x0020: 'HIGH_ENTROPY_VA', 0x0040: 'DYNAMIC_BASE (ASLR)',
    0x0100: 'NX_COMPAT (DEP)', 0x0200: 'NO_SEH',
    0x0400: 'NO_BIND', 0x0800: 'APPCONTAINER',
    0x1000: 'WDM_DRIVER', 0x2000: 'GUARD_CF (CFG)',
    0x4000: 'TERMINAL_SERVER_AWARE',
}

DIRECTORY_NAMES = [
    'IMAGE_DIRECTORY_ENTRY_EXPORT', 'IMAGE_DIRECTORY_ENTRY_IMPORT',
    'IMAGE_DIRECTORY_ENTRY_RESOURCE', 'IMAGE_DIRECTORY_ENTRY_EXCEPTION',
    'IMAGE_DIRECTORY_ENTRY_SECURITY', 'IMAGE_DIRECTORY_ENTRY_BASERELOC',
    'IMAGE_DIRECTORY_ENTRY_DEBUG', 'IMAGE_DIRECTORY_ENTRY_ARCHITECTURE',
    'IMAGE_DIRECTORY_ENTRY_GLOBALPTR', 'IMAGE_DIRECTORY_ENTRY_TLS',
    'IMAGE_DIRECTORY_ENTRY_LOAD_CONFIG', 'IMAGE_DIRECTORY_ENTRY_BOUND_IMPORT',
    'IMAGE_DIRECTORY_ENTRY_IAT', 'IMAGE_DIRECTORY_ENTRY_DELAY_IMPORT',
    'IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR',
]

RESOURCE_TYPES = {
    1: 'RT_CURSOR', 2: 'RT_BITMAP', 3: 'RT_ICON', 4: 'RT_MENU',
    5: 'RT_DIALOG', 6: 'RT_STRING', 7: 'RT_FONTDIR', 8: 'RT_FONT',
    9: 'RT_ACCELERATOR', 10: 'RT_RCDATA', 11: 'RT_MESSAGETABLE',
    12: 'RT_GROUP_CURSOR', 14: 'RT_GROUP_ICON', 16: 'RT_VERSION',
    17: 'RT_DLGINCLUDE', 19: 'RT_PLUGPLAY', 20: 'RT_VXD',
    21: 'RT_ANICURSOR', 22: 'RT_ANIICON', 23: 'RT_HTML',
    24: 'RT_MANIFEST',
}


# ============================================================
# Hashing / basic info
# ============================================================

def compute_hashes(data: bytes) -> dict:
    return {
        'md5': hashlib.md5(data).hexdigest(),
        'sha1': hashlib.sha1(data).hexdigest(),
        'sha256': hashlib.sha256(data).hexdigest(),
        'sha512': hashlib.sha512(data).hexdigest(),
        'size_bytes': len(data),
        'ssdeep': _try_ssdeep(data),
    }


def _try_ssdeep(data):
    try:
        import ssdeep
        return ssdeep.hash(data)
    except Exception:
        return None


def identify_file_type(data: bytes) -> str:
    for magic, name in MAGIC_EXES.items():
        if data.startswith(magic):
            return name
    return 'Unknown (not a recognized executable format)'


# ============================================================
# PE header analysis
# ============================================================

def analyze_headers(pe: pefile.PE, data: bytes) -> dict:
    hdr = {}
    dos = pe.DOS_HEADER
    fh = pe.FILE_HEADER
    oh = pe.OPTIONAL_HEADER

    hdr['dos_header'] = {
        'e_magic': hex(dos.e_magic),
        'e_cblp': dos.e_cblp, 'e_cp': dos.e_cp,
        'e_lfanew': hex(dos.e_lfanew),
    }

    machine = fh.Machine
    arch = MACHINE_TYPES.get(machine, hex(machine))
    arch_bitness = {
        0x014c: 32, 0x8664: 64, 0x01c0: 32, 0xaa64: 64,
        0x01c4: 32, 0x0200: 64,
    }.get(machine, None)

    is_dotnet = False
    try:
        is_dotnet = bool(oh.DATA_DIRECTORY[14].VirtualAddress != 0)
    except Exception:
        pass

    hdr['file_header'] = {
        'machine': hex(machine),
        'architecture': arch,
        'architecture_bits': arch_bitness,
        'number_of_sections': fh.NumberOfSections,
        'time_date_stamp': fh.TimeDateStamp,
        'time_date_stamp_iso': datetime.datetime.fromtimestamp(
            fh.TimeDateStamp, datetime.timezone.utc).isoformat() if 0 < fh.TimeDateStamp < 2**31 else 'invalid',
        'characteristics': [n for bit, n in CHARACTERISTICS.items()
                            if fh.Characteristics & bit],
        'is_dll': bool(fh.Characteristics & 0x2000),
        'is_dotnet': is_dotnet,
        'subsystem': SUBSYSTEMS.get(oh.Subsystem, hex(oh.Subsystem)),
        'is_signed': len(data) > 0 and _has_security_directory(pe),
    }

    hdr['optional_header'] = {
        'magic': hex(oh.Magic),  # 0x10b = PE32, 0x20b = PE32+
        'format': 'PE32+ (64-bit)' if oh.Magic == 0x20b else 'PE32 (32-bit)',
        'linker_version': f'{oh.MajorLinkerVersion}.{oh.MinorLinkerVersion}',
        'size_of_code': oh.SizeOfCode,
        'address_of_entry_point': hex(oh.AddressOfEntryPoint),
        'image_base': hex(oh.ImageBase),
        'section_alignment': hex(oh.SectionAlignment),
        'file_alignment': hex(oh.FileAlignment),
        'subsystem_version': f'{oh.MajorSubsystemVersion}.{oh.MinorSubsystemVersion}',
        'size_of_image': oh.SizeOfImage,
        'checksum': hex(oh.CheckSum),
        'checksum_valid': pe.generate_checksum() == oh.CheckSum,
        'dll_characteristics': [n for bit, n in DLL_CHARACTERISTICS.items()
                                if oh.DllCharacteristics & bit],
        'stack_reserve': oh.SizeOfStackReserve,
        'heap_reserve': oh.SizeOfHeapReserve,
    }

    # Data directories
    dirs = []
    for i, d in enumerate(oh.DATA_DIRECTORY[:15]):
        if d.VirtualAddress or d.Size:
            dirs.append({
                'index': i,
                'name': DIRECTORY_NAMES[i] if i < len(DIRECTORY_NAMES) else f'DIR_{i}',
                'virtual_address': hex(d.VirtualAddress),
                'rva': d.VirtualAddress,
                'size': d.Size,
            })
    hdr['data_directories'] = dirs

    # Sections
    sections = []
    for s in pe.sections:
        flags = [n for bit, n in SECTION_FLAGS.items() if s.Characteristics & bit]
        entropy = s.get_entropy()
        sections.append({
            'name': s.Name.decode('utf-8', 'ignore').rstrip('\x00'),
            'virtual_address': hex(s.VirtualAddress),
            'virtual_size': s.Misc_VirtualSize,
            'raw_size': s.SizeOfRawData,
            'raw_offset': hex(s.PointerToRawData),
            'characteristics': flags,
            'entropy': round(entropy, 4),
            'high_entropy_warning': entropy > 7.0 and s.SizeOfRawData > 512,
            'md5': hashlib.md5(s.get_data()).hexdigest(),
        })
    hdr['sections'] = sections

    # Overlay detection
    overlay_offset = pe.get_overlay_data_start_offset()
    hdr['overlay'] = {
        'present': overlay_offset is not None,
        'offset': hex(overlay_offset) if overlay_offset is not None else None,
        'size': len(data) - overlay_offset if overlay_offset else 0,
    }

    # Packer heuristics
    hdr['packer_heuristics'] = detect_packer(data, hdr, pe)
    return hdr


def _has_security_directory(pe) -> bool:
    try:
        d = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]  # SECURITY
        return d.VirtualAddress != 0 and d.Size != 0
    except Exception:
        return False


def detect_packer(data, hdr, pe) -> list:
    heur = []
    sec_names = [s['name'].lower() for s in hdr['sections']]
    known_packer_sections = {
        'upx0': 'UPX', 'upx1': 'UPX', 'upx!': 'UPX',
        'aspack': 'ASPack', '.aspack': 'ASPack',
        'themida': 'Themida', 'vmp0': 'VMProtect', 'vmp1': 'VMProtect',
        '.vmp0': 'VMProtect', '.vmp1': 'VMProtect',
        '.themida': 'Themida', '.nsp0': 'NsPack', 'nsp1': 'NsPack',
        'pebundle': 'PEBundle', 'mew': 'MEW', '.mew': 'MEW',
        '.upx': 'UPX', '.aspack': 'ASPack', 'adata': 'ASPack/dIE',
        '.petite': 'Petite', '.packed': 'Generic packed',
        'fsg.': 'FSG', '.fsg': 'FSG', '.mpress1': 'MPRESS',
        '.mpress2': 'MPRESS', 'pec2': 'PECompact', 'pec1': 'PECompact',
    }
    for n in sec_names:
        for key, packer in known_packer_sections.items():
            if key in n:
                if packer not in heur:
                    heur.append(packer)

    high_entropy_non_code = [
        s for s in hdr['sections']
        if s['entropy'] > 7.2 and s['raw_size'] > 1024
    ]
    if high_entropy_non_code and 'UPX' not in heur:
        heur.append('High-entropy sections (possible packing/encryption): '
                    + ', '.join(s['name'] for s in high_entropy_non_code))

    if hdr['overlay']['present'] and hdr['overlay']['size'] > 65536:
        heur.append(f"Large overlay ({hdr['overlay']['size']} bytes) - "
                    "possible self-extracting installer or embedded payload")
    if not hdr['sections'] or hdr['file_header']['number_of_sections'] < 3:
        heur.append('Unusually low section count')
    if hdr['optional_header']['address_of_entry_point'] == '0x0':
        heur.append('Entry point at 0x0 (typical for pure resource DLLs or unusual packers)')
    return heur


# ============================================================
# Imports / Exports
# ============================================================

def analyze_imports(pe) -> list:
    imports = []
    if not hasattr(pe, 'DIRECTORY_ENTRY_IMPORT'):
        return imports
    for entry in pe.DIRECTORY_ENTRY_IMPORT:
        dll = entry.dll.decode('utf-8', 'ignore') if entry.dll else '???'
        funcs = []
        for imp in entry.imports:
            name = imp.name.decode('utf-8', 'ignore') if imp.name else f'ord#{imp.ordinal}'
            funcs.append({'name': name, 'ordinal': imp.ordinal,
                          'address': hex(imp.address) if imp.address else None})
        imports.append({'dll': dll, 'functions': funcs,
                        'count': len(funcs)})
    return imports


def analyze_exports(pe) -> dict:
    exports = []
    if not hasattr(pe, 'DIRECTORY_ENTRY_EXPORT'):
        return {'dll_name': None, 'symbols': exports}
    exp_dir = pe.DIRECTORY_ENTRY_EXPORT
    dll_name = exp_dir.name.decode('utf-8', 'ignore') if exp_dir.name else None
    for exp in getattr(exp_dir, 'symbols', []):
        exports.append({
            'name': exp.name.decode('utf-8', 'ignore') if exp.name else None,
            'ordinal': exp.ordinal,
            'address': hex(exp.address) if exp.address is not None else None,
        })
    return {'dll_name': dll_name, 'symbols': exports}


# ============================================================
# Resources
# ============================================================

def analyze_resources(pe, out_dir) -> list:
    results = []
    if not hasattr(pe, 'DIRECTORY_ENTRY_RESOURCE'):
        return results

    res_dir = out_dir / 'resources'
    res_dir.mkdir(parents=True, exist_ok=True)

    def walk(entries, path_ids, level=0):
        for entry in entries:
            eid = entry.id if entry.id is not None else entry.name
            new_path = path_ids + [str(eid)]
            if hasattr(entry, 'directory') and entry.directory:
                walk(entry.directory.entries, new_path, level + 1)
            elif hasattr(entry, 'data'):
                data_entry = entry.data.struct
                rva = data_entry.OffsetToData
                size = data_entry.Size
                try:
                    raw = pe.get_data(rva, size)
                except Exception:
                    continue
                # Determine type
                rtype = path_ids[0] if path_ids else '?'
                try:
                    rtype = int(rtype)
                except (ValueError, TypeError):
                    pass
                type_name = RESOURCE_TYPES.get(rtype, f'TYPE_{rtype}')

                # Special: RT_VERSION parse
                extra = {}
                if rtype == 16:
                    extra['version_info'] = parse_version_info(raw)

                ext_map = {2: '.bmp', 3: '.ico', 14: '.ico', 16: '.res',
                           23: '.html', 24: '.manifest', 10: '.bin',
                           11: '.msgtable', 6: '.stringtable'}
                ext = ext_map.get(rtype, '.bin')
                if raw[:2] == b'MZ':
                    ext = '.exe'
                fname = f'rt{rtype}_{"_".join(new_path[1:])}{ext}'
                fname = re.sub(r'[^\w.\-]', '_', fname)
                fpath = res_dir / fname
                fpath.write_bytes(raw)

                results.append({
                    'type_id': rtype,
                    'type_name': type_name,
                    'path': '/'.join(new_path),
                    'size': size,
                    'rva': hex(rva),
                    'saved_to': str(fpath),
                    'md5': hashlib.md5(raw).hexdigest(),
                    **extra,
                })

    walk(pe.DIRECTORY_ENTRY_RESOURCE.entries, [])
    return results


def parse_version_info(raw: bytes) -> dict:
    """Rudimentary VS_VERSIONINFO parser."""
    out = {}
    try:
        text = raw.decode('utf-16-le', 'ignore')
        for key in ('CompanyName', 'FileDescription', 'FileVersion',
                    'InternalName', 'LegalCopyright', 'OriginalFilename',
                    'ProductName', 'ProductVersion', 'Comments',
                    'LegalTrademarks', 'PrivateBuild', 'SpecialBuild'):
            m = re.search(re.escape(key) + r'\x00+\x00(.{0,200}?)\x00\x00', text)
            if m:
                out[key] = m.group(1).replace('\x00', '').strip()
    except Exception:
        pass
    return out


# ============================================================
# Strings
# ============================================================

ASCII_RE = re.compile(rb'[\x20-\x7e]{4,}')
UTF16_RE = re.compile(rb'(?:[\x20-\x7e]\x00){4,}')
URL_RE = re.compile(rb'(?:https?|ftp)://[^\s"\'<>]{4,}', re.I)
IP_RE = re.compile(rb'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_RE = re.compile(rb'[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}')
REGISTRY_RE = re.compile(rb'HKEY_[A-Z_\\]+[A-Za-z0-9_\\ \-.]*')
FILEPATH_RE = re.compile(rb'[A-Za-z]:\\[^\x00-\x1f"\'<>|]{2,}')
MZ_REF_RE = re.compile(rb'This program cannot be run in DOS mode')


def extract_strings(data: bytes, min_len: int = 4, max_results: int = 5000) -> dict:
    ascii_strings = [m.group().decode('ascii') for m in ASCII_RE.finditer(data)]
    utf16_strings = [m.group().decode('utf-16-le', 'ignore')
                     for m in UTF16_RE.finditer(data)]
    all_s = ascii_strings + utf16_strings

    strings = {
        'counts': {
            'ascii': len(ascii_strings),
            'utf16': len(utf16_strings),
            'total': len(all_s),
        },
        'urls': sorted({m.group().decode('ascii', 'ignore')
                        for m in URL_RE.finditer(data)})[:200],
        'ips': sorted({m.group().decode('ascii')
                       for m in IP_RE.finditer(data)})[:200],
        'emails': sorted({m.group().decode('ascii')
                          for m in EMAIL_RE.finditer(data)})[:100],
        'registry_keys': sorted({m.group().decode('ascii', 'ignore')
                                 for m in REGISTRY_RE.finditer(data)})[:100],
        'file_paths': sorted({m.group().decode('ascii', 'ignore')
                              for m in FILEPATH_RE.finditer(data)})[:200],
        'sample_ascii': ascii_strings[:max_results],
        'sample_utf16': utf16_strings[:max_results // 2],
    }

    # Suspicious indicators
    suspicious_keywords = [
        'CreateRemoteThread', 'WriteProcessMemory', 'VirtualAllocEx',
        'SetWindowsHookEx', 'GetAsyncKeyState', 'keylog', 'ransom',
        'bitcoin', 'wallet', 'cmd.exe', '/c del', 'vssadmin', 'bcdedit',
        'wbem', 'schtasks', 'RunOnce', 'CurrentVersion\\Run',
        'powershell -enc', 'IEX', 'Invoke-Expression', 'FromBase64String',
        'socks', 'bind', 'reverse', 'shell', 'backdoor', 'inject',
    ]
    joined = '\n'.join(all_s).lower()
    strings['suspicious_keywords'] = [
        kw for kw in suspicious_keywords if kw.lower() in joined
    ]
    return strings


# ============================================================
# Digital signature
# ============================================================

def analyze_signature(pe, data: bytes) -> dict:
    sig = {'signed': False}
    try:
        sec_dir = pe.OPTIONAL_HEADER.DATA_DIRECTORY[4]
        if sec_dir.VirtualAddress == 0 or sec_dir.Size == 0:
            return sig

        sig['signed'] = True
        offset = sec_dir.VirtualAddress  # SECURITY dir uses file offset
        blob = data[offset:offset + sec_dir.Size]

        # WIN_CERTIFICATE structure
        if len(blob) >= 8:
            length, revision, cert_type = struct.unpack('<IHH', blob[:8])
            sig['certificate_entry'] = {
                'length': length,
                'revision': {0x0100: '1.0 (legacy)', 0x0200: '2.0'}.get(revision, hex(revision)),
                'type': {0x0002: 'PKCS_SIGNED_DATA (Authenticode)',
                         0x0003: 'TS_STACK_SIGNED',
                         0x0004: 'PKCS1_SIGN_ONLY'}.get(cert_type, hex(cert_type)),
            }
            pkcs_blob = blob[8:8 + length - 8] if length <= len(blob) else blob[8:]
            sig['authenticode_blob_sha256'] = hashlib.sha256(pkcs_blob).hexdigest()
            sig['authenticode_blob_size'] = len(pkcs_blob)

        # Try to parse PKCS#7 for certificate details (requires cryptography lib)
        sig.update(_parse_pkcs7(pkcs_blob if len(blob) >= 8 else blob))

        # Windows WinVerifyTrust (only works on Windows)
        sig['windows_verification'] = _win_verify_trust(
            data if isinstance(data, str) else getattr(pe, '__file_path', None))
    except Exception as e:
        sig['error'] = f'{type(e).__name__}: {e}'
    return sig


def _parse_pkcs7(blob: bytes) -> dict:
    out = {}
    try:
        from cryptography.hazmat.primitives.serialization import pkcs7
        certs = pkcs7.load_der_pkcs7_certificates(blob)
        out['certificates'] = []
        for cert in certs:
            subject = cert.subject.rfc4514_string()
            issuer = cert.issuer.rfc4514_string()
            out['certificates'].append({
                'subject': subject,
                'issuer': issuer,
                'serial': hex(cert.serial_number),
                'not_valid_before': cert.not_valid_before_utc.isoformat()
                    if hasattr(cert, 'not_valid_before_utc') else str(cert.not_valid_before),
                'not_valid_after': cert.not_valid_after_utc.isoformat()
                    if hasattr(cert, 'not_valid_after_utc') else str(cert.not_valid_after),
                'sha256_fingerprint': cert.fingerprint(
                    __import__('hashlib').sha256()).hex(':'),
            })
    except ImportError:
        out['pkcs7_note'] = 'Install "cryptography" to parse certificate details.'
    except Exception as e:
        out['pkcs7_error'] = f'{type(e).__name__}: {e}'
    return out


def _win_verify_trust(path) -> dict:
    """Authenticode verification via WinVerifyTrust (Windows only)."""
    if sys.platform != 'win32' or not path or not os.path.exists(path):
        return {'available': False,
                'note': 'WinVerifyTrust requires Windows and a real file path'}
    try:
        import ctypes.wintypes as wt
        wintrust = ctypes.windll.wintrust
        crypt32 = ctypes.windll.crypt32

        class WINTRUST_FILE_INFO(ctypes.Structure):
            _fields_ = [('cbStruct', wt.DWORD), ('pcwszFilePath', wt.LPCWSTR),
                        ('hFile', wt.HANDLE), ('pgKnownSubject', ctypes.c_void_p)]

        class WINTRUST_DATA(ctypes.Structure):
            class _u(ctypes.Union):
                _fields_ = [('pFile', ctypes.POINTER(WINTRUST_FILE_INFO))]
            _anonymous_ = ('u',)
            _fields_ = [('cbStruct', wt.DWORD),
                        ('dwUIChoice', wt.DWORD),
                        ('fdwRevocationChecks', wt.DWORD),
                        ('dwUnionChoice', wt.DWORD),
                        ('u', _u),
                        ('dwStateAction', wt.DWORD),
                        ('hWVTStateData', wt.HANDLE),
                        ('pwszURLReference', ctypes.c_void_p),
                        ('dwProvFlags', wt.DWORD),
                        ('dwUIContext', wt.DWORD),
                        ('pSignatureSettings', ctypes.c_void_p)]

        WTD_UI_NONE = 2
        WTD_REVOKE_NONE = 0
        WTD_CHOICE_FILE = 1
        WTD_SAFER_FLAG = 0x100
        TRUST_E_NOSIGNATURE = 0x800B0100
        TRUST_E_PROVIDER_UNKNOWN = 0x800B0001
        TRUST_E_SUBJECT_FORM_UNKNOWN = 0x800B0003

        f = WINTRUST_FILE_INFO(ctypes.sizeof(WINTRUST_FILE_INFO), path)
        wd = WINTRUST_DATA()
        wd.cbStruct = ctypes.sizeof(WINTRUST_DATA)
        wd.dwUIChoice = WTD_UI_NONE
        wd.fdwRevocationChecks = WTD_REVOKE_NONE
        wd.dwUnionChoice = WTD_CHOICE_FILE
        wd.pFile = ctypes.pointer(f)
        wd.dwProvFlags = WTD_SAFER_FLAG

        GUID_WINTRUST_ACTION = (ctypes.c_ubyte * 16)(
            0xAC, 0xC5, 0x6B, 0x64, 0xD6, 0x7C, 0x4C, 0x2B,
            0x8B, 0xB4, 0xB4, 0xFB, 0x6D, 0x0F, 0x0A, 0xC7)

        ret = wintrust.WinVerifyTrust(ctypes.c_void_p(None),
                                      ctypes.cast(GUID_WINTRUST_ACTION, ctypes.c_void_p),
                                      ctypes.byref(wd))
        status_map = {
            0: 'VERIFIED - signature valid and trusted',
            TRUST_E_NOSIGNATURE: 'NOT SIGNED (or signature unreadable)',
            TRUST_E_PROVIDER_UNKNOWN: 'Provider unknown',
            TRUST_E_SUBJECT_FORM_UNKNOWN: 'Subject form unknown',
        }
        return {
            'available': True,
            'winverifytrust_result': hex(ret & 0xFFFFFFFF),
            'status': status_map.get(ret, f'UNTRUSTED / ERROR (0x{ret & 0xFFFFFFFF:08x})'),
        }
    except Exception as e:
        return {'available': False, 'error': f'{type(e).__name__}: {e}'}


# ============================================================
# Embedded file extraction
# ============================================================

def extract_embedded_files(data: bytes, out_dir) -> list:
    found = []
    embed_dir = out_dir / 'embedded'
    embed_dir.mkdir(parents=True, exist_ok=True)

    for magic, label, skip, _ in EMBEDDED_MAGICS:
        start = 0
        count = 0
        while True:
            idx = data.find(magic, start)
            if idx < 0:
                break
            start = idx + 1
            count += 1
            if count > 10:  # cap per-type
                break
            ext = {'zip': '.zip', 'cab': '.cab', 'rar': '.rar', '7z': '.7z',
                   'png': '.png', 'jpeg': '.jpg', 'pdf': '.pdf',
                   'embedded_pe': '.exe', 'ole_cfb': '.doc'}.get(label, '.bin')
            fname = f'embedded_{label}_{idx}{ext}'
            fpath = embed_dir / fname

            # Determine blob extent
            blob = _slice_blob(data, idx, label)
            if not blob or len(blob) < 16:
                continue
            fpath.write_bytes(blob)
            found.append({
                'type': label,
                'offset': hex(idx),
                'size': len(blob),
                'md5': hashlib.md5(blob).hexdigest(),
                'sha256': hashlib.sha256(blob).hexdigest(),
                'saved_to': str(fpath),
            })

    # Attempt to actually extract archives
    extracted = _extract_archives(found, embed_dir)
    for f in found:
        f['extracted_contents'] = extracted.get(f['saved_to'], [])
    return found


def _slice_blob(data: bytes, idx: int, label: str) -> bytes:
    """Extract a plausible blob starting at idx based on container type."""
    if label == 'cab':
        return _extract_cab_blob(data, idx)
    if label == 'zip':
        return _extract_zip_blob(data, idx)
    if label == 'embedded_pe':
        return _extract_pe_blob(data, idx)
    if label in ('gzip', 'bzip2', 'xz', 'zstd'):
        # Try streaming decompress to bound the blob
        return _decompress_stream(data, idx, label)
    # Fallback: to next embedded magic or end, bounded
    end = len(data)
    next_mz = data.find(b'MZ', idx + 2)
    if 0 < next_mz < end and label not in ('pdf',):
        # don't cut archives arbitrarily; keep whole overlay for archives
        end = min(end, idx + max(len(data) - idx, 1024))
    return data[idx:end]


def _extract_cab_blob(data: bytes, idx: int) -> bytes:
    """Parse MSCF header to get the exact CAB size."""
    try:
        # CFHEADER: signature(4) reserved1(4) cbCabinet(4) ...
        cb_cabinet = struct.unpack('<I', data[idx + 8: idx + 12])[0]
        if 0 < cb_cabinet <= len(data) - idx + 64:
            end = idx + cb_cabinet
            if end <= len(data):
                return data[idx:end]
    except Exception:
        pass
    return data[idx:idx + 1024 * 1024]  # fallback 1 MB


def _extract_zip_blob(data: bytes, idx: int) -> bytes:
    """Use End-of-Central-Directory to find the zip extent."""
    eocd = data.find(b'PK\x05\x06', idx)
    if eocd > 0:
        try:
            comment_len = struct.unpack('<H', data[eocd + 20: eocd + 22])[0]
            end = eocd + 22 + comment_len
            return data[idx:end]
        except Exception:
            pass
    return data[idx:idx + 1024 * 1024]


def _extract_pe_blob(data: bytes, idx: int) -> bytes:
    """Estimate PE size from OptionalHeader.SizeOfImage or section table."""
    try:
        if data[idx:idx + 2] != b'MZ':
            return b''
        e_lfanew = struct.unpack('<I', data[idx + 0x3c: idx + 0x40])[0]
        pe_off = idx + e_lfanew
        if data[pe_off:pe_off + 4] != b'PE\x00\x00':
            return data[idx:idx + 4096]
        num_sections = struct.unpack('<H', data[pe_off + 6: pe_off + 8])[0]
        opt_size = struct.unpack('<H', data[pe_off + 20: pe_off + 22])[0]
        sec_off = pe_off + 24 + opt_size
        max_end = 0
        for i in range(num_sections):
            s = sec_off + i * 40
            raw_size, raw_ptr = struct.unpack('<II', data[s + 16: s + 24])
            max_end = max(max_end, raw_ptr + raw_size)
        end = idx + max(0x400, max_end)
        if end <= len(data):
            return data[idx:end]
    except Exception:
        pass
    return data[idx:idx + 8192]


def _decompress_stream(data: bytes, idx: int, label: str) -> bytes:
    import gzip, bz2, lzma
    decompressors = {
        'gzip': gzip.GzipFile, 'bzip2': bz2.BZ2File, 'xz': lzma.LZMAFile,
    }
    cls = decompressors.get(label)
    if cls is None:
        return data[idx:idx + 65536]
    try:
        with cls(fileobj=BytesIO(data[idx:])) as f:
            out = f.read(10 * 1024 * 1024)  # 10 MB cap
        return out
    except Exception:
        return data[idx:idx + 65536]


def _extract_archives(found: list, embed_dir) -> dict:
    """Extract CAB/ZIP payloads to <embed_dir>/extracted/..."""
    results = {}
    extract_root = embed_dir / 'extracted'
    cab_tool = shutil.which('cabextract') or shutil.which('7z') or shutil.which('expand')
    zip_ok = True
    try:
        import zipfile  # noqa
    except ImportError:
        zip_ok = False

    for item in found:
        src = item['saved_to']
        if not os.path.exists(src):
            continue
        dest = os.path.join(str(extract_root),
                            os.path.basename(src) + '_contents')
        os.makedirs(dest, exist_ok=True)
        contents = []
        try:
            if item['type'] == 'zip' and zip_ok:
                import zipfile
                with zipfile.ZipFile(src) as z:
                    z.extractall(dest)
                    contents = z.namelist()
            elif item['type'] == 'cab' and cab_tool:
                import subprocess
                if cab_tool.endswith(('cabextract', 'expand')):
                    subprocess.run([cab_tool, src, f'-d{dest}' if cab_tool.endswith('cabextract') else dest],
                                   capture_output=True, timeout=60)
                else:  # 7z
                    subprocess.run([cab_tool, 'x', src, f'-o{dest}', '-y'],
                                   capture_output=True, timeout=60)
                for root, _, files in os.walk(dest):
                    for f in files:
                        contents.append(os.path.relpath(os.path.join(root, f), dest))
        except Exception as e:
            contents = [f'<extraction failed: {e}>']
        results[src] = contents
    return results


# ============================================================
# .NET analysis
# ============================================================

def analyze_dotnet(path: str) -> dict:
    if not HAS_DNFILE:
        return {'available': False, 'note': 'pip install dnfile'}
    out = {}
    try:
        dnet = dnfile.dnPE(path)
        md = dnet.net.mdtables
        out['runtime_version'] = (str(dnet.net.struct.MajorRuntimeVersion)
                                  + '.' + str(dnet.net.struct.MinorRuntimeVersion))
        out['metadata_version'] = dnet.net.metadata.struct.Version.decode('utf-8', 'ignore')
        if md.Assembly:
            a = md.Assembly.rows[0]
            out['assembly_name'] = str(a.Name)
            out['assembly_version'] = f'{a.MajorVersion}.{a.MinorVersion}.{a.BuildNumber}.{a.RevisionNumber}'
        if md.TypeDef:
            out['types'] = [str(t.TypeNamespace) + '.' + str(t.TypeName)
                            for t in md.TypeDef.rows[:200]]
        if md.ManagedResources:
            out['managed_resources'] = [str(r.Name) for r in md.ManagedResources.rows]
    except Exception as e:
        out['error'] = f'{type(e).__name__}: {e}'
    return out


# ============================================================
# Disassembly (entry point)
# ============================================================

def disassemble_entry(pe, max_instructions: int = 100) -> dict:
    try:
        ep = pe.OPTIONAL_HEADER.AddressOfEntryPoint
        if ep == 0:
            return {'note': 'Entry point is 0'}
        machine = pe.FILE_HEADER.Machine
        mode_map = {
            0x014c: capstone.CS_MODE_32, 0x8664: capstone.CS_MODE_64,
            0x01c0: capstone.CS_MODE_ARM, 0xaa64: capstone.CS_MODE_ARM,
        }
        if machine not in mode_map:
            return {'note': f'Unsupported arch {hex(machine)} for capstone disasm'}
        data = pe.get_memory_mapped_image()[ep: ep + max_instructions * 16]
        md = capstone.Cs(capstone.CS_ARCH_X86 if machine in (0x014c, 0x8664)
                         else capstone.CS_ARCH_ARM, mode_map[machine])
        if machine == 0xaa64:
            md = capstone.Cs(capstone.CS_ARCH_ARM64, capstone.CS_MODE_LITTLE_ENDIAN)
        insns = []
        image_base = pe.OPTIONAL_HEADER.ImageBase
        for i in md.disasm(data, image_base + ep):
            insns.append(f'0x{i.address:x}:\t{i.mnemonic}\t{i.op_str}')
            if len(insns) >= max_instructions:
                break
        return {'entry_point_va': hex(image_base + ep), 'instructions': insns}
    except Exception as e:
        return {'error': f'{type(e).__name__}: {e}'}


# ============================================================
# Report generators
# ============================================================

def _json_safe(o):
    if isinstance(o, bytes):
        return o.hex()
    if isinstance(o, dict):
        return {k: _json_safe(v) for k, v in o.items()}
    if isinstance(o, (list, tuple)):
        return [_json_safe(x) for x in o]
    return o


def write_json(result: dict, path: str):
    with open(path, 'w', encoding='utf-8') as f:
        json.dump(_json_safe(result), f, indent=2, ensure_ascii=False, default=str)


def write_txt(result: dict, path: str):
    lines = []
    a = lines.append

    def section(title):
        a('=' * 70)
        a(title)
        a('=' * 70)

    a('PE ANALYSIS REPORT')
    a(f'Generated: {result["meta"]["generated"]}')
    a(f'Tool: {result["meta"]["tool"]}')
    a('')

    section('FILE')
    for k, v in result['file'].items():
        a(f'  {k}: {v}')
    a('')

    section('HASHES')
    for k, v in result['hashes'].items():
        a(f'  {k}: {v}')
    a('')

    h = result['headers']
    section('ARCHITECTURE')
    a(f"  Architecture : {h['file_header']['architecture']}")
    a(f"  Bits         : {h['file_header']['architecture_bits']}")
    a(f"  Format       : {h['optional_header']['format']}")
    a(f"  Subsystem    : {h['file_header']['subsystem']}")
    a(f"  DLL          : {h['file_header']['is_dll']}")
    a(f"  .NET         : {h['file_header']['is_dotnet']}")
    a(f"  Compiled     : {h['file_header']['time_date_stamp_iso']}")
    a('')

    section('PACKER HEURISTICS')
    if h['packer_heuristics']:
        for p in h['packer_heuristics']:
            a(f'  [!] {p}')
    else:
        a('  (none detected)')
    a('')

    section('SECTIONS')
    a(f"  {'Name':<10} {'VirtAddr':>10} {'VirtSize':>10} {'RawSize':>10} {'Entropy':>8}")
    for s in h['sections']:
        warn = ' <-- HIGH' if s['high_entropy_warning'] else ''
        a(f"  {s['name']:<10} {s['virtual_address']:>10} {s['virtual_size']:>10} "
          f"{s['raw_size']:>10} {s['entropy']:>8}{warn}")
    a('')

    section('IMPORTS')
    for imp in result['imports']:
        a(f"  {imp['dll']} ({imp['count']} functions)")
        for f_ in imp['functions']:
            a(f"      {f_['name']}")
    a('')

    section('EXPORTS')
    exp = result['exports']
    if exp.get('symbols'):
        a(f"  DLL name: {exp['dll_name']}")
        for e in exp['symbols']:
            a(f"  ord {e['ordinal']}: {e['name']} @ {e['address']}")
    else:
        a('  (no exports)')
    a('')

    section('DIGITAL SIGNATURE')
    s = result['signature']
    a(f"  Signed: {s.get('signed', False)}")
    for cert in s.get('certificates', []):
        a(f"  Subject : {cert['subject']}")
        a(f"  Issuer  : {cert['issuer']}")
        a(f"  Valid   : {cert['not_valid_before']} -> {cert['not_valid_after']}")
        a(f"  SHA256  : {cert['sha256_fingerprint']}")
    if 'windows_verification' in s:
        wv = s['windows_verification']
        if wv.get('available'):
            a(f"  WinVerifyTrust: {wv['status']}")
    for k in ('certificate_entry', 'error', 'pkcs7_note'):
        if k in s:
            a(f'  {k}: {s[k]}')
    a('')

    section('RESOURCES (extracted)')
    if result['resources']:
        for r in result['resources']:
            a(f"  {r['type_name']:<16} path={r['path']:<20} size={r['size']:<8} -> {r['saved_to']}")
            if 'version_info' in r:
                for k, v in r['version_info'].items():
                    a(f'      {k}: {v}')
    else:
        a('  (none)')
    a('')

    section('EMBEDDED FILES (extracted)')
    if result['embedded_files']:
        for e in result['embedded_files']:
            a(f"  {e['type']:<14} offset={e['offset']:<10} size={e['size']:<10} -> {e['saved_to']}")
            for c in e.get('extracted_contents', [])[:20]:
                a(f'      extracted: {c}')
    else:
        a('  (none)')
    a('')

    section('INDICATORS FROM STRINGS')
    st = result['strings']
    for key in ('urls', 'ips', 'emails', 'registry_keys', 'file_paths', 'suspicious_keywords'):
        vals = st.get(key, [])
        a(f'  {key} ({len(vals)}):')
        for v in vals[:50]:
            a(f'      {v}')
    a('')

    section('.NET')
    dn = result.get('dotnet', {})
    if dn.get('available', True):
        for k, v in dn.items():
            if k in ('types', 'managed_resources'):
                a(f'  {k}: {", ".join(v[:30])}')
            else:
                a(f'  {k}: {v}')
    else:
        a(f"  {dn.get('note', 'not a .NET assembly')}")
    a('')

    section('DISASSEMBLY (entry point)')
    dis = result.get('disassembly', {})
    a(f"  {dis.get('entry_point_va', dis.get('note', dis.get('error', '')))}")
    for ins in dis.get('instructions', [])[:100]:
        a(f'    {ins}')

    with open(path, 'w', encoding='utf-8') as f:
        f.write('\n'.join(lines))


def write_html(result: dict, path: str):
    def esc(x):
        return (str(x).replace('&', '&amp;').replace('<', '&lt;')
                .replace('>', '&gt;'))
    h = result['headers']
    rows = []

    def table(headers_, data_rows, cls=''):
        t = f'<table class="{cls}"><tr>' + ''.join(
            f'<th>{esc(x)}</th>' for x in headers_) + '</tr>'
        for r in data_rows:
            t += '<tr>' + ''.join(f'<td>{esc(x)}</td>' for x in r) + '</tr>'
        return t + '</table>'

    summary_cards = f'''
    <div class="cards">
      <div class="card"><div class="big">{esc(h['file_header']['architecture'])}</div><div>Architecture</div></div>
      <div class="card"><div class="big">{esc(h['optional_header']['format'])}</div><div>Format</div></div>
      <div class="card"><div class="big">{'YES' if result['signature'].get('signed') else 'NO'}</div><div>Signed</div></div>
      <div class="card"><div class="big">{esc(h['file_header']['subsystem'])}</div><div>Subsystem</div></div>
      <div class="card"><div class="big">{len(result['sections']) if False else len(h['sections'])}</div><div>Sections</div></div>
      <div class="card"><div class="big">{len(result['embedded_files'])}</div><div>Embedded</div></div>
    </div>'''

    # Sections table
    rows.append('<h2>Sections</h2>')
    rows.append(table(['Name', 'VirtAddr', 'VirtSize', 'RawSize', 'Entropy', 'Flags', 'MD5'],
                      [[s['name'], s['virtual_address'], s['virtual_size'],
                        s['raw_size'],
                        f"{s['entropy']}{' ⚠' if s['high_entropy_warning'] else ''}",
                        ', '.join(s['characteristics']), s['md5']]
                       for s in h['sections']]))

    rows.append('<h2>Packer Heuristics</h2>')
    rows.append('<ul>' + ''.join(f'<li class="warn">{esc(p)}</li>'
                                 for p in h['packer_heuristics']) + '</ul>'
                if h['packer_heuristics'] else '<p>None detected.</p>')

    rows.append('<h2>Imports</h2>')
    imp_rows = [[i['dll'], i['count'],
                 ', '.join(f['name'] for f in i['functions'][:40]) +
                 (' ...' if i['count'] > 40 else '')]
                for i in result['imports']]
    rows.append(table(['DLL', 'Count', 'Functions'], imp_rows))

    rows.append('<h2>Exports</h2>')
    exp = result['exports']
    rows.append(table(['Ordinal', 'Name', 'Address'],
                      [[e['ordinal'], e['name'] or f"#{e['ordinal']}", e['address']]
                       for e in exp.get('symbols', [])]) if exp.get('symbols')
                else '<p>No exports.</p>')

    rows.append('<h2>Digital Signature</h2>')
    s = result['signature']
    sig_rows = [['Signed', s.get('signed', False)]]
    for c in s.get('certificates', []):
        sig_rows += [['Subject', c['subject']], ['Issuer', c['issuer']],
                     ['Valid', f"{c['not_valid_before']} → {c['not_valid_after']}"],
                     ['SHA256 FP', c['sha256_fingerprint']]]
    wv = s.get('windows_verification', {})
    if wv.get('available'):
        sig_rows.append(['WinVerifyTrust', wv['status']])
    if 'certificate_entry' in s:
        ce = s['certificate_entry']
        sig_rows.append(['Cert entry', f"{ce['type']} rev {ce['revision']} len {ce['length']}"])
    rows.append(table(['Field', 'Value'], sig_rows))

    rows.append('<h2>Resources (extracted)</h2>')
    res_rows = [[r['type_name'], r['path'], r['size'], r['rva'], r['saved_to'],
                 '<br>'.join(f'{k}: {esc(v)}' for k, v in r.get('version_info', {}).items())]
                for r in result['resources']]
    rows.append(table(['Type', 'Path', 'Size', 'RVA', 'Saved To', 'Version Info'],
                      res_rows) if res_rows else '<p>None.</p>')

    rows.append('<h2>Embedded Files (extracted)</h2>')
    emb_rows = []
    for e in result['embedded_files']:
        emb_rows.append([e['type'], e['offset'], e['size'], e['md5'], e['saved_to'],
                         '<br>'.join(e.get('extracted_contents', [])[:15])])
    rows.append(table(['Type', 'Offset', 'Size', 'MD5', 'Saved To', 'Extracted'],
                      emb_rows) if emb_rows else '<p>None.</p>')

    rows.append('<h2>Indicators from Strings</h2>')
    st = result['strings']
    for key in ('urls', 'ips', 'emails', 'registry_keys', 'file_paths', 'suspicious_keywords'):
        vals = st.get(key, [])
        if vals:
            rows.append(f'<h3>{esc(key)} ({len(vals)})</h3><ul>' +
                        ''.join(f'<li>{esc(v)}</li>' for v in vals[:60]) + '</ul>')

    rows.append('<h2>Disassembly (entry point)</h2>')
    dis = result.get('disassembly', {})
    if 'instructions' in dis:
        rows.append(f"<p>Entry point VA: <code>{dis['entry_point_va']}</code></p><pre>" +
                    '\n'.join(dis['instructions']) + '</pre>')
    else:
        rows.append(f"<p>{esc(dis.get('note', dis.get('error', 'n/a')))}</p>")

    rows.append('<h2>Hashes</h2>')
    rows.append(table(['Algorithm', 'Value'],
                      [[k, v] for k, v in result['hashes'].items()]))


    dn = result.get('dotnet', {})
    if dn:
        rows.append('<h2>.NET Metadata</h2>')
        rows.append(table(['Field', 'Value'],
                          [[k, (', '.join(v[:30]) + ' ...' if isinstance(v, list) and len(v) > 30
                                else ', '.join(v) if isinstance(v, list) else v)]
                           for k, v in dn.items()]))

    html = f'''<!DOCTYPE html>
<html><head><meta charset="utf-8"><title>PE Analysis Report - {esc(result['file']['name'])}</title>
<style>
 body {{ font-family: 'Segoe UI', sans-serif; margin: 2em; background:#111; color:#ddd; }}
 h1,h2,h3 {{ color:#00d47e; border-bottom:1px solid #333; padding-bottom:4px;}}
 table {{ border-collapse: collapse; width: 100%; margin: 1em 0; }}
 th, td {{ border: 1px solid #333; padding: 6px 10px; text-align: left; font-size: 0.9em; word-break: break-all; }}
 th {{ background: #1c1c1c; color: #00d47e; }}
 tr:nth-child(even) {{ background: #181818; }}
 .cards {{ display: flex; gap: 12px; flex-wrap: wrap; margin: 1em 0; }}
 .card {{ background: #1a1a2e; border: 1px solid #00d47e44; border-radius: 8px;
          padding: 12px 20px; min-width: 140px; text-align:center; }}
 .big {{ font-size: 1.4em; color:#00d47e; font-weight:bold; }}
 .warn {{ color: #ffcc00; }}
 pre {{ background: #181818; border:1px solid #333; padding: 10px; overflow-x:auto; font-size:0.85em; }}
</style></head><body>
<h1>PE Analysis Report</h1>
<p>{esc(result['file']['path'])}<br>Generated {esc(result['meta']['generated'])} by {esc(result['meta']['tool'])}</p>
{summary_cards}
{''.join(rows)}
</body></html>'''
    with open(path, 'w', encoding='utf-8') as f:
        f.write(html)


def write_pdf(result: dict, path: str):
    if not HAS_REPORTLAB:
        # Fallback: rename txt
        alt = path.replace('.pdf', '.txt')
        write_txt(result, alt)
        return alt

    h = result['headers']
    doc = SimpleDocTemplate(path, pagesize=letter,
                            leftMargin=0.6 * inch, rightMargin=0.6 * inch,
                            topMargin=0.6 * inch, bottomMargin=0.6 * inch)
    styles = getSampleStyleSheet()
    h1 = ParagraphStyle('h1', parent=styles['Heading1'], textColor=colors.HexColor('#0a6e46'))
    h2 = ParagraphStyle('h2', parent=styles['Heading2'], textColor=colors.HexColor('#0a6e46'))
    small = ParagraphStyle('small', parent=styles['Normal'], fontSize=7, leading=9)
    mono = ParagraphStyle('mono', parent=styles['Code'], fontSize=6.5, leading=8.5)

    story = []
    story.append(Paragraph('PE Analysis Report', h1))
    story.append(Paragraph(
        f"File: {result['file']['path']}<br/>"
        f"Generated: {result['meta']['generated']}<br/>"
        f"Tool: {result['meta']['tool']}", styles['Normal']))
    story.append(Spacer(1, 12))

    def add_table(title, headers, data, style_small=True):
        story.append(Paragraph(title, h2))
        if not data:
            story.append(Paragraph('None.', styles['Normal']))
            story.append(Spacer(1, 10))
            return
        body_style = small if style_small else styles['Normal']
        tdata = [[Paragraph(f'<b>{x}</b>', body_style) for x in headers]]
        for row in data:
            tdata.append([Paragraph(str(x), body_style) for x in row])
        t = Table(tdata, colWidths=[min(1.2 * inch * len(headers), 7.2 * inch / len(headers))] * len(headers))
        t.setStyle(TableStyle([
            ('GRID', (0, 0), (-1, -1), 0.4, colors.grey),
            ('BACKGROUND', (0, 0), (-1, 0), colors.HexColor('#dfeee8')),
            ('VALIGN', (0, 0), (-1, -1), 'TOP'),
        ]))
        story.append(t)
        story.append(Spacer(1, 12))

    fh = h['file_header']; oh = h['optional_header']
    add_table('Identification', ['Property', 'Value'], [
        ['File', result['file']['name']],
        ['Type', result['file']['type']],
        ['Size', f"{result['hashes']['size_bytes']:,} bytes"],
        ['Architecture', f"{fh['architecture']} ({fh['architecture_bits']}-bit)"],
        ['Format', oh['format']],
        ['Subsystem', fh['subsystem']],
        ['DLL', fh['is_dll']],
        ['.NET', fh['is_dotnet']],
        ['Compiled', fh['time_date_stamp_iso']],
        ['Linker', oh['linker_version']],
        ['Entry Point', oh['address_of_entry_point']],
        ['Checksum valid', oh['checksum_valid']],
        ['Signed', result['signature'].get('signed', False)],
    ], style_small=False)

    add_table('Hashes', ['Algorithm', 'Value'],
              [[k, v] for k, v in result['hashes'].items()])

    add_table('Sections', ['Name', 'VirtAddr', 'VirtSize', 'RawSize', 'Entropy', 'Flags'],
              [[s['name'], s['virtual_address'], s['virtual_size'], s['raw_size'],
                f"{s['entropy']}{' HIGH' if s['high_entropy_warning'] else ''}",
                ', '.join(s['characteristics'])] for s in h['sections']])

    if h['packer_heuristics']:
        add_table('Packer Heuristics', ['#', 'Finding'],
                  [[i + 1, p] for i, p in enumerate(h['packer_heuristics'])])

    story.append(PageBreak())
    add_table('Imports', ['DLL', 'Count', 'Functions'],
              [[i['dll'], i['count'],
                ', '.join(f['name'] for f in i['functions'][:50]) +
                (' ...' if i['count'] > 50 else '')]
               for i in result['imports']])

    exp = result['exports']
    add_table('Exports', ['Ordinal', 'Name', 'Address'],
              [[e['ordinal'], e['name'] or f"#{e['ordinal']}", e['address']]
               for e in exp.get('symbols', [])])

    s = result['signature']
    sig_data = [['Signed', s.get('signed', False)]]
    for c in s.get('certificates', []):
        sig_data += [['Subject', c['subject']], ['Issuer', c['issuer']],
                     ['Valid', f"{c['not_valid_before']} to {c['not_valid_after']}"],
                     ['SHA256 FP', c['sha256_fingerprint']]]
    wv = s.get('windows_verification', {})
    if wv.get('available'):
        sig_data.append(['WinVerifyTrust', wv['status']])
    add_table('Digital Signature', ['Field', 'Value'], sig_data)

    add_table('Resources (extracted)', ['Type', 'Path', 'Size', 'Saved To'],
              [[r['type_name'], r['path'], r['size'], r['saved_to']]
               for r in result['resources']])

    add_table('Embedded Files (extracted)', ['Type', 'Offset', 'Size', 'MD5', 'Saved To'],
              [[e['type'], e['offset'], e['size'], e['md5'], e['saved_to']]
               for e in result['embedded_files']])

    st = result['strings']
    add_table('Indicators from Strings', ['Category', 'Values'],
              [[k, '; '.join(str(v) for v in st.get(k, [])[:30])]
               for k in ('urls', 'ips', 'emails', 'registry_keys',
                         'file_paths', 'suspicious_keywords')
               if st.get(k)])

    story.append(Paragraph('Disassembly (entry point)', h2))
    dis = result.get('disassembly', {})
    if 'instructions' in dis:
        story.append(Paragraph(f"Entry point VA: {dis['entry_point_va']}", styles['Normal']))
        story.append(Paragraph('<br/>'.join(dis['instructions'][:100]), mono))
    else:
        story.append(Paragraph(str(dis.get('note', dis.get('error', 'n/a'))), styles['Normal']))

    doc.build(story)
    return path


# ============================================================
# Main
# ============================================================

def analyze(path: str, out_dir: str = None, verbose: bool = True) -> dict:
    path = os.path.abspath(path)
    if not os.path.exists(path):
        raise FileNotFoundError(path)

    if out_dir is None:
        base = os.path.splitext(os.path.basename(path))[0]
        out_dir = os.path.join(os.path.dirname(path) or '.', f'{base}_analysis')
    out_dir = os.path.abspath(out_dir)
    os.makedirs(out_dir, exist_ok=True)
    out_dir_obj = __import__('pathlib').Path(out_dir)

    data = open(path, 'rb').read()
    result = {
        'meta': {
            'generated': datetime.datetime.now().isoformat(),
            'tool': 'pe_decompiler.py v1.0',
            'source_file': path,
            'output_dir': out_dir,
        },
        'file': {
            'name': os.path.basename(path),
            'path': path,
            'type': identify_file_type(data),
            'magic': data[:2].hex(),
        },
        'hashes': compute_hashes(data),
        'headers': {}, 'imports': [], 'exports': {}, 'resources': [],
        'embedded_files': [], 'signature': {}, 'strings': {},
        'dotnet': {}, 'disassembly': {},
    }

    if result['file']['type'] == 'Unknown (not a recognized executable format)':
        # Still do strings + embedded scan, no PE parsing
        result['strings'] = extract_strings(data)
        result['embedded_files'] = extract_embedded_files(data, out_dir_obj)
        return result

    pe = pefile.PE(path, fast_load=False)
    pe.__file_path = path  # stash for WinVerifyTrust

    if verbose:
        print(f'[*] Analyzing {path}')
        print(f'[*] Type: {result["file"]["type"]}')

    result['headers'] = analyze_headers(pe, data)
    result['imports'] = analyze_imports(pe)
    result['exports'] = analyze_exports(pe)
    result['resources'] = analyze_resources(pe, out_dir_obj)
    result['signature'] = analyze_signature(pe, data)
    result['embedded_files'] = extract_embedded_files(data, out_dir_obj)
    result['strings'] = extract_strings(data)
    result['disassembly'] = disassemble_entry(pe)

    if result['headers']['file_header']['is_dotnet']:
        result['dotnet'] = analyze_dotnet(path)
        result['dotnet']['available'] = True

    pe.close()

    if verbose:
        n_res = len(result['resources'])
        n_emb = len(result['embedded_files'])
        n_imp = sum(i['count'] for i in result['imports'])
        print(f'[*] Sections: {len(result["headers"]["sections"])}, '
              f'Imports: {n_imp}, Exports: {len(result["exports"].get("symbols", []))}')
        print(f'[*] Resources extracted: {n_res}, Embedded files: {n_emb}')
        print(f'[*] Signed: {result["signature"].get("signed", False)}')

    # ---- Generate all report formats ----
    base = os.path.join(out_dir, 'report')
    write_json(result, base + '.json')
    write_txt(result, base + '.txt')
    write_html(result, base + '.html')
    pdf = write_pdf(result, base + '.pdf')
    if verbose:
        print(f'[*] Reports written:')
        for ext in ('json', 'txt', 'html', 'pdf'):
            p = f'{base}.{ext}'
            if os.path.exists(p):
                print(f'    {p}')
    return result


def main():
    import argparse
    parser = argparse.ArgumentParser(
        description='PE Decompiler / Analyzer - extracts embedded files, analyzes '
                    'PE headers, signature, strings, resources, imports/exports. '
                    'Outputs HTML/JSON/TXT/PDF.')
    parser.add_argument('file', help='Path to the EXE/PE file to analyze')
    parser.add_argument('-o', '--output', default=None,
                        help='Output directory (default: <file>_analysis)')
    parser.add_argument('-q', '--quiet', action='store_true')
    args = parser.parse_args()

    try:
        result = analyze(args.file, args.output, verbose=not args.quiet)
        h = result['headers']
        print()
        print(f"  File        : {result['file']['name']}")
        print(f"  Type        : {result['file']['type']}")
        if h:
            print(f"  Arch        : {h['file_header']['architecture']} "
                  f"({h['optional_header']['format']})")
            print(f"  Subsystem   : {h['file_header']['subsystem']}")
            print(f"  .NET        : {h['file_header']['is_dotnet']}")
            print(f"  Signed      : {result['signature'].get('signed', False)}")
            if h['packer_heuristics']:
                print(f"  Packer      : {', '.join(h['packer_heuristics'][:3])}")
        print(f"  SHA256      : {result['hashes']['sha256']}")
        print(f"\n  Output dir  : {result['meta']['output_dir']}")
    except Exception as e:
        print(f'[!] Error: {e}', file=sys.stderr)
        if not args.quiet:
            traceback.print_exc()
        sys.exit(1)


if __name__ == '__main__':
    main()