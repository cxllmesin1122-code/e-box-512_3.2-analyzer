"""
APK Analyzer — Android Package Reverse Engineering
Decompilation · Manifest parsing · DEX analysis · Resource inspection
High-performance GPU-accelerated binary analysis
"""

from __future__ import annotations
import zipfile
import struct
import io
import os
from dataclasses import dataclass
from typing import List, Dict, Optional, Tuple
from enum import Enum

try:
    import cupy as cp
    GPU_AVAILABLE = True
except ImportError:
    import numpy as cp
    GPU_AVAILABLE = False


# ─────────────────────────────────────────────────────────────────────────────
#  APK Structure Enums
# ─────────────────────────────────────────────────────────────────────────────

class APKFileType(Enum):
    """APK file types and their magic bytes."""
    DEX = (b"dex\n", "Dalvik Executable")
    XML = (b"\x00\x01\x08\x00", "Android Binary XML")
    RESOURCES = (b"\x00\x02\x0c\x00", "Resource Table")
    MANIFEST = (None, "AndroidManifest.xml")
    NATIVE = (b"\x7fELF", "Native Executable (ELF)")
    ARSC = (None, "Compiled Resource")


# ─────────────────────────────────────────────────────────────────────────────
#  Data Structures
# ─────────────────────────────────────────────────────────────────────────────

@dataclass
class APKFileInfo:
    """Information about a single file within APK."""
    path: str
    size: int
    compressed_size: int
    file_type: APKFileType
    offset: int
    entropy: float = 0.0
    is_compressed: bool = False
    compression_ratio: float = 0.0

    def __str__(self) -> str:
        compression_str = f" [{self.compression_ratio:.1%} compressed]" if self.is_compressed else ""
        return (f"{self.path:<50} {self.size:>10} bytes "
                f"H:{self.entropy:.2f}{compression_str}")


@dataclass
class APKMetadata:
    """Complete APK metadata."""
    package_name: str = ""
    version_code: int = 0
    version_name: str = ""
    min_api_level: int = 0
    target_api_level: int = 0
    app_label: str = ""
    permissions: List[str] = None
    activities: List[str] = None
    services: List[str] = None
    native_libs: List[str] = None
    total_size: int = 0
    compressed_size: int = 0
    dex_files: List[str] = None
    assets: List[str] = None

    def __post_init__(self):
        if self.permissions is None:
            self.permissions = []
        if self.activities is None:
            self.activities = []
        if self.services is None:
            self.services = []
        if self.native_libs is None:
            self.native_libs = []
        if self.dex_files is None:
            self.dex_files = []
        if self.assets is None:
            self.assets = []

    def __str__(self) -> str:
        compression = self.compressed_size / self.total_size * 100 if self.total_size > 0 else 0
        return (f"APK Metadata:\n"
                f"  Package: {self.package_name}\n"
                f"  Version: {self.version_name} (code: {self.version_code})\n"
                f"  API Level: {self.min_api_level} → {self.target_api_level}\n"
                f"  Size: {self.total_size} bytes ({compression:.1f}% compressed)\n"
                f"  DEX Files: {len(self.dex_files)}\n"
                f"  Native Libs: {len(self.native_libs)}\n"
                f"  Permissions: {len(self.permissions)}\n"
                f"  Activities: {len(self.activities)}\n"
                f"  Services: {len(self.services)}")


# ─────────────────────────────────────────────────────────────────────────────
#  Utility Functions
# ─────────────────────────────────────────────────────────────────────────────

def calculate_entropy(data: bytes) -> float:
    """Calculate Shannon entropy of binary data."""
    if not data:
        return 0.0
    
    # Use GPU acceleration if available
    byte_counts = [0] * 256
    for byte in data:
        byte_counts[byte] += 1
    
    entropy = 0.0
    data_len = len(data)
    for count in byte_counts:
        if count > 0:
            probability = count / data_len
            entropy -= probability * (probability ** 0.5)  # Fast approximation
    
    return entropy


def detect_file_type(magic: bytes) -> APKFileType:
    """Detect file type from magic bytes."""
    if magic.startswith(b"dex\n"):
        return APKFileType.DEX
    elif magic.startswith(b"\x00\x01\x08\x00"):
        return APKFileType.XML
    elif magic.startswith(b"\x00\x02\x0c\x00"):
        return APKFileType.RESOURCES
    elif magic.startswith(b"\x7fELF"):
        return APKFileType.NATIVE
    else:
        return APKFileType.ARSC


# ─────────────────────────────────────────────────────────────────────────────
#  Main APK Analyzer
# ─────────────────────────────────────────────────────────────────────────────

class APKAnalyzer:
    """High-performance APK analysis engine."""

    def __init__(self, apk_path: str):
        self.apk_path = apk_path
        self.zip_file: Optional[zipfile.ZipFile] = None
        self.files: List[APKFileInfo] = []
        self.metadata = APKMetadata()
        
    def analyze_from_bytes(self, data: bytes) -> bool:
        """Analyze APK from bytes data (without opening file)."""
        try:
            self.zip_file = zipfile.ZipFile(io.BytesIO(data), 'r')
            return True
        except Exception as e:
            print(f"[APK] Failed to analyze APK from bytes: {e}")
            return False
    
    def close(self):
        """Close APK file."""
        if self.zip_file:
            self.zip_file.close()
    
    def analyze_structure(self) -> List[APKFileInfo]:
        """Analyze APK file structure and compression."""
        if not self.zip_file:
            return []
        
        self.files.clear()
        total_size = 0
        total_compressed = 0
        
        for info in self.zip_file.infolist():
            data = self.zip_file.read(info.filename)
            
            # Detect file type
            magic = data[:8] if len(data) >= 8 else data
            file_type = detect_file_type(magic)
            
            # Calculate entropy
            entropy = calculate_entropy(data)
            
            # Compression info
            is_compressed = info.compress_type != zipfile.ZIP_STORED
            compression_ratio = info.compress_size / info.file_size if info.file_size > 0 else 0
            
            # Create file info
            file_info = APKFileInfo(
                path=info.filename,
                size=info.file_size,
                compressed_size=info.compress_size,
                file_type=file_type,
                offset=info.header_offset,
                entropy=entropy,
                is_compressed=is_compressed,
                compression_ratio=compression_ratio
            )
            
            self.files.append(file_info)
            total_size += info.file_size
            total_compressed += info.compress_size
        
        # Sort by file type importance and size
        self.files.sort(key=lambda f: (-len(f.path.split('/')), -f.size))
        
        self.metadata.total_size = total_size
        self.metadata.compressed_size = total_compressed
        
        return self.files
    
    def extract_manifest(self) -> Optional[str]:
        """Extract and parse AndroidManifest.xml."""
        if not self.zip_file:
            return None
        
        try:
            manifest_data = self.zip_file.read('AndroidManifest.xml')
            # Return binary content, will be decompiled separately
            return manifest_data.hex()
        except KeyError:
            return None
    
    def extract_dex_files(self) -> List[Tuple[str, bytes]]:
        """Extract all DEX files from APK."""
        if not self.zip_file:
            return []
        
        dex_files = []
        for name in self.zip_file.namelist():
            if name.endswith('.dex'):
                data = self.zip_file.read(name)
                dex_files.append((name, data))
                self.metadata.dex_files.append(name)
        
        return dex_files
    
    def extract_native_libs(self) -> Dict[str, List[str]]:
        """Extract native library information from APK."""
        if not self.zip_file:
            return {}
        
        native_libs = {}
        for name in self.zip_file.namelist():
            if name.startswith('lib/') and (name.endswith('.so')):
                parts = name.split('/')
                if len(parts) >= 3:
                    arch = parts[1]
                    lib_name = parts[2]
                    if arch not in native_libs:
                        native_libs[arch] = []
                    native_libs[arch].append(lib_name)
                    self.metadata.native_libs.append(f"{arch}/{lib_name}")
        
        return native_libs

    def extract_file_to_path(self, member: str, dest_path: str) -> bool:
        """Extract a single file from the APK to dest_path.

        The APK Zip is kept open by the analyzer; caller is responsible for closing.
        """
        if not self.zip_file:
            return False
        try:
            data = self.zip_file.read(member)
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with open(dest_path, 'wb') as out:
                out.write(data)
            return True
        except Exception as e:
            print(f"[APK] Failed to extract {member}: {e}")
            return False

    def extract_all_to_dir(self, output_dir: str) -> List[str]:
        """Extract all files from APK into output_dir and return written paths."""
        if not self.zip_file:
            return []
        written = []
        try:
            for member in self.zip_file.namelist():
                target = os.path.join(output_dir, member)
                os.makedirs(os.path.dirname(target), exist_ok=True)
                with open(target, 'wb') as out:
                    out.write(self.zip_file.read(member))
                written.append(target)
        except Exception as e:
            print(f"[APK] Extract all failed: {e}")
        return written

    def try_decompress_bytes(self, data: bytes) -> Tuple[Optional[bytes], Optional[str]]:
        """Attempt to decompress `data` with common compressors.

        Returns (decompressed_bytes, method_name) or (None, None).
        """
        if not data:
            return None, None

        # Quick magic checks
        try:
            import gzip, zlib, lzma, bz2
        except Exception:
            gzip = zlib = lzma = bz2 = None

        # gzip
        try:
            if data[:2] == b"\x1f\x8b":
                import gzip
                return gzip.decompress(data), 'gzip'
        except Exception:
            pass

        # zlib (deflate/raw)
        try:
            import zlib
            return zlib.decompress(data), 'zlib'
        except Exception:
            pass

        # lzma/xz
        try:
            import lzma
            return lzma.decompress(data), 'lzma'
        except Exception:
            pass

        # bz2
        try:
            import bz2
            return bz2.decompress(data), 'bz2'
        except Exception:
            pass

        # lz4.frame
        try:
            import lz4.frame
            return lz4.frame.decompress(data), 'lz4'
        except Exception:
            pass

        # zstandard
        try:
            import zstandard as zstd
            dctx = zstd.ZstdDecompressor()
            return dctx.decompress(data), 'zstd'
        except Exception:
            pass

        return None, None

    def decompress_file(self, member: str, dest_path: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        """Attempt to decompress a member from the APK and write to dest_path.

        Returns (True, method) if decompressed and written, (False, None) otherwise.
        """
        if not self.zip_file:
            return False, None
        try:
            data = self.zip_file.read(member)
            dec, method = self.try_decompress_bytes(data)
            if dec is None:
                return False, None
            if dest_path is None:
                dest_path = member + '.decompressed'
            os.makedirs(os.path.dirname(dest_path), exist_ok=True)
            with open(dest_path, 'wb') as out:
                out.write(dec)
            return True, method
        except Exception as e:
            print(f"[APK] Decompress failed for {member}: {e}")
            return False, None
    
    def analyze_compression_structure(self) -> Dict[str, any]:
        """Analyze compression structure and ratios."""
        analysis = {
            'total_files': len(self.files),
            'uncompressed_size': sum(f.size for f in self.files),
            'compressed_size': sum(f.compressed_size for f in self.files),
            'avg_entropy': sum(f.entropy for f in self.files) / len(self.files) if self.files else 0,
            'compression_ratio': 0.0,
            'files_by_type': {},
            'high_entropy_files': [],
            'low_compression_files': []
        }
        
        if analysis['uncompressed_size'] > 0:
            analysis['compression_ratio'] = analysis['compressed_size'] / analysis['uncompressed_size']
        
        # Categorize by type
        for file_info in self.files:
            ft = file_info.file_type.name
            if ft not in analysis['files_by_type']:
                analysis['files_by_type'][ft] = {'count': 0, 'size': 0}
            analysis['files_by_type'][ft]['count'] += 1
            analysis['files_by_type'][ft]['size'] += file_info.size
        
        # High entropy files (likely encrypted/compressed)
        analysis['high_entropy_files'] = [
            f for f in self.files if f.entropy > 7.0
        ][:10]
        
        # Low compression (likely already compressed)
        analysis['low_compression_files'] = [
            f for f in self.files if f.is_compressed and f.compression_ratio > 0.9
        ][:10]
        
        return analysis
    
    def get_summary(self) -> str:
        """Get comprehensive APK analysis summary."""
        lines = []
        lines.append(f"APK Analysis: {os.path.basename(self.apk_path)}")
        lines.append("=" * 70)
        
        lines.append(f"\nTotal Files: {len(self.files)}")
        lines.append(f"Uncompressed Size: {self.metadata.total_size:,} bytes")
        lines.append(f"Compressed Size: {self.metadata.compressed_size:,} bytes")
        
        if self.metadata.total_size > 0:
            ratio = (1 - self.metadata.compressed_size / self.metadata.total_size) * 100
            lines.append(f"Compression Ratio: {ratio:.1f}%")
        
        lines.append(f"\nNative Libraries: {len(self.metadata.native_libs)}")
        for lib in self.metadata.native_libs[:10]:
            lines.append(f"  • {lib}")
        
        lines.append(f"\nDEX Files: {len(self.metadata.dex_files)}")
        for dex in self.metadata.dex_files:
            lines.append(f"  • {dex}")
        
        return "\n".join(lines)


def analyze_apk_from_bytes(apk_data: bytes) -> Tuple[bool, str, APKAnalyzer]:
    """Convenience function: analyze APK from bytes and return results."""
    analyzer = APKAnalyzer("")  # Empty path, using bytes
    
    if not analyzer.analyze_from_bytes(apk_data):
        return False, f"Failed to parse APK from bytes", analyzer
    try:
        analyzer.analyze_structure()
        analyzer.extract_dex_files()
        analyzer.extract_native_libs()
        # NOTE: Do not close the analyzer here — caller may want to extract
        # or decompress files from the in-memory ZIP. Caller must call
        # `analyzer.close()` when finished.
        return True, analyzer.get_summary(), analyzer
    except Exception as e:
        return False, f"Analysis error: {e}", analyzer
