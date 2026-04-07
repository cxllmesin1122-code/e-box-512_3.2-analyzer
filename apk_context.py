"""
Central APK context shared across application features.

Provides a thread-safe wrapper around an `APKAnalyzer` instance and
convenience helpers for extraction and decompression so all modules
can access APK content consistently.
"""
from __future__ import annotations
import threading
import tempfile
import os
from typing import Optional, Tuple, List

from apk_analyzer import APKAnalyzer


class APKContext:
    def __init__(self):
        self._lock = threading.RLock()
        self.analyzer: Optional[APKAnalyzer] = None
        self.extract_dir: Optional[str] = None

    def set_analyzer(self, analyzer: APKAnalyzer):
        with self._lock:
            # Close previous analyzer if different
            if self.analyzer and self.analyzer is not analyzer:
                try:
                    self.analyzer.close()
                except Exception:
                    pass
            self.analyzer = analyzer

    def get_analyzer(self) -> Optional[APKAnalyzer]:
        with self._lock:
            return self.analyzer

    def clear(self):
        with self._lock:
            if self.analyzer:
                try:
                    self.analyzer.close()
                except Exception:
                    pass
            self.analyzer = None
            self.extract_dir = None

    def extract_all(self, outdir: Optional[str] = None) -> Tuple[List[str], Optional[str]]:
        with self._lock:
            if not self.analyzer:
                return [], None
            if not outdir:
                outdir = tempfile.mkdtemp(prefix='apk_extract_')
            written = self.analyzer.extract_all_to_dir(outdir)
            if written:
                self.extract_dir = outdir
            return written, outdir

    def extract_member(self, member: str, dest: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        with self._lock:
            if not self.analyzer:
                return False, None
            if dest is None:
                if not self.extract_dir:
                    self.extract_dir = tempfile.mkdtemp(prefix='apk_extract_')
                dest = os.path.join(self.extract_dir, member)
            ok = self.analyzer.extract_file_to_path(member, dest)
            return ok, dest if ok else None

    def decompress_member(self, member: str, dest: Optional[str] = None) -> Tuple[bool, Optional[str]]:
        with self._lock:
            if not self.analyzer:
                return False, None
            if dest is None:
                if not self.extract_dir:
                    self.extract_dir = tempfile.mkdtemp(prefix='apk_extract_')
                dest = os.path.join(self.extract_dir, member + '.decompressed')
            ok, method = self.analyzer.decompress_file(member, dest)
            return ok, dest if ok else None

    def list_dex_files(self) -> List[str]:
        with self._lock:
            if not self.analyzer:
                return []
            dex = [name for name, _ in self.analyzer.extract_dex_files()]
            return dex


# Global singleton for convenience across modules
global_apk_context = APKContext()
