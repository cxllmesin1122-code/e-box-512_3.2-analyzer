#!/usr/bin/env python3
"""Create a test binary with malware-like characteristics"""

# Create a test ELF binary that might trigger some malware signals
elf_header = bytes([
    0x7f, 0x45, 0x4c, 0x46,  # ELF magic
    0x02, 0x01, 0x01, 0x00,  # 64-bit, little-endian, current version
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # padding
    0x02, 0x00,              # executable file
    0x3e, 0x00,              # x86-64 architecture
    0x01, 0x00, 0x00, 0x00,  # version
    0x00, 0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # entry point (0x1000)
    0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # program header offset
    0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,  # section header offset
    0x00, 0x00, 0x00, 0x00,  # flags
    0x40, 0x00,              # ELF header size
    0x38, 0x00,              # program header entry size
    0x01, 0x00,              # number of program header entries
    0x00, 0x00,              # section header entry size
    0x00, 0x00,              # number of section header entries
    0x00, 0x00,              # section header string table index
])

# Add some padding and then high-entropy "malware-like" data
suspicious_code = b'\xE8\x00\x00\x00\x00\x5D\x81\xED' * 32  # repeated malware signature
random_like = bytes([i ^ 0xAA for i in range(256)] * 16)  # high entropy section

test_binary = elf_header + b'\x00' * 512 + suspicious_code + random_like

# Write test binary
with open('test_binary_malware.elf', 'wb') as f:
    f.write(test_binary)

print(f"✓ Created test_binary_malware.elf ({len(test_binary)} bytes)")
