"""
Purge Studio — Engine Kernel Hook
Initializes native camouflage loader for sealed runtime modules.
"""

import sys
import os
import marshal
import zlib
import hashlib
import importlib.abc
import importlib.machinery
from pathlib import Path

SALT = b"PurgeStudio-Camouflage-2026"

MODULE_MAP = {
    "engine.image_processor": "k_img_0x9a4f.dat",
    "engine.batch_orchestrator": "k_orc_0x3e1b.dat",
    "engine.hot_patcher": "k_upd_0x7c8a.dat",
    "engine.patch_crypto": "k_sec_0x5f2d.dat",
}

def _unseal_data(sealed_bytes: bytes) -> bytes:
    if not sealed_bytes.startswith(b"PSDAT\x01"):
        raise ValueError("Corrupted module signature.")
    seed = int.from_bytes(sealed_bytes[6:10], "big")
    ciphertext = sealed_bytes[10:]
    key = hashlib.sha256(f"KernelKey-{seed}".encode() + SALT).digest()
    
    keystream = bytearray()
    idx = 0
    while len(keystream) < len(ciphertext):
        keystream.extend(hashlib.sha256(key + idx.to_bytes(4, "big")).digest())
        idx += 1
        
    compressed = bytes(b ^ k for b, k in zip(ciphertext, keystream[:len(ciphertext)]))
    return zlib.decompress(compressed)

class _CamouflageLoader(importlib.abc.Loader):
    def __init__(self, fullname: str, data_path: Path):
        self.fullname = fullname
        self.data_path = data_path

    def create_module(self, spec):
        return None

    def exec_module(self, module):
        sealed_bytes = self.data_path.read_bytes()
        raw_bc = _unseal_data(sealed_bytes)
        code_obj = marshal.loads(raw_bc)
        
        module.__file__ = str(self.data_path)
        if "." in self.fullname:
            module.__package__ = self.fullname.rsplit(".", 1)[0]
        else:
            module.__package__ = ""
            
        exec(code_obj, module.__dict__)

class _CamouflageFinder(importlib.abc.MetaPathFinder):
    def __init__(self, storage_dirs: list):
        self.storage_dirs = storage_dirs

    def find_spec(self, fullname, path, target=None):
        if fullname in MODULE_MAP:
            fname = MODULE_MAP[fullname]
            for s_dir in self.storage_dirs:
                candidate = s_dir / fname
                if candidate.exists():
                    return importlib.machinery.ModuleSpec(
                        fullname,
                        _CamouflageLoader(fullname, candidate),
                        origin=str(candidate)
                    )
        return None

# Discover runtime directory
_CUR_DIR = Path(__file__).resolve().parent
_CANDIDATE_DIRS = [
    _CUR_DIR / "runtime",
    _CUR_DIR.parent / "runtime",
    _CUR_DIR.parent / "_internal" / "runtime"
]
_VALID_DIRS = [d for d in _CANDIDATE_DIRS if d.exists()]

if _VALID_DIRS:
    if not any(isinstance(f, _CamouflageFinder) for f in sys.meta_path):
        sys.meta_path.insert(0, _CamouflageFinder(_VALID_DIRS))
