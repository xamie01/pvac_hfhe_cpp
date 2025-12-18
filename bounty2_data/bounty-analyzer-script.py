#!/usr/bin/env python3
"""
PVAC-HFHE Bounty Challenge Analyzer
Analyzes a.ct and b.ct files for the $3,333 bounty
"""

import struct
import sys
from pathlib import Path
from typing import List, Tuple

def read_file(filename: str) -> bytes:
    """Read binary file"""
    try:
        with open(filename, 'rb') as f:
            return f.read()
    except FileNotFoundError:
        print(f"Error: {filename} not found!")
        print("Please download a.ct and b.ct from:")
        print("https://github.com/octra-labs/pvac_hfhe_cpp/tree/main/bounty2_data")
        sys.exit(1)

def parse_as_integers(data: bytes, int_type: str = 'q') -> List[int]:
    """Parse binary data as array of integers
    
    Args:
        data: Binary data
        int_type: 'q' (int64), 'i' (int32), 'h' (int16), 'Q' (uint64), etc.
    """
    size = struct.calcsize(int_type)
    values = []
    for i in range(0, len(data) - size + 1, size):
        try:
            val = struct.unpack(f'<{int_type}', data[i:i+size])[0]
            values.append((i, val))
        except struct.error:
            break
    return values

def find_suspicious_values(data: bytes, min_val: int = 1_000_000, 
                          max_val: int = 10**15) -> List[Tuple[int, int]]:
    """Find values that could be plaintexts (not too small, not maxed out)"""
    candidates = []
    
    # Try unsigned int64
    for offset in range(0, len(data) - 8, 8):
        val = struct.unpack('<Q', data[offset:offset+8])[0]
        if min_val < val < max_val:
            candidates.append((offset, val))
    
    # Try signed int64
    for offset in range(0, len(data) - 8, 8):
        val = struct.unpack('<q', data[offset:offset+8])[0]
        if min_val < abs(val) < max_val:
            candidates.append((offset, val))
    
    return candidates

def analyze_structure(data: bytes, name: str):
    """Analyze file structure"""
    print(f"\n{'='*60}")
    print(f"Analyzing {name}")
    print(f"{'='*60}")
    
    print(f"\n[+] File size: {len(data)} bytes ({len(data)/1024:.2f} KB)")
    
    # Show hex dump of start and end
    print(f"\n[+] First 64 bytes (hex):")
    print("   ", data[:64].hex())
    print(f"\n[+] Last 64 bytes (hex):")
    print("   ", data[-64:].hex())
    
    # Entropy check (rough)
    byte_freq = [0] * 256
    for b in data[:10000]:  # Sample first 10KB
        byte_freq[b] += 1
    
    non_zero = sum(1 for f in byte_freq if f > 0)
    print(f"\n[+] Entropy indicators:")
    print(f"    Unique bytes in first 10KB: {non_zero}/256")
    print(f"    Zeros: {byte_freq[0]}, 255s: {byte_freq[255]}")
    
    # Parse as different integer types
    print(f"\n[+] First 10 values as int64 (signed):")
    vals = parse_as_integers(data, 'q')[:10]
    for offset, val in vals:
        print(f"    Offset {offset:4d}: {val:20d} (0x{val & 0xFFFFFFFFFFFFFFFF:016x})")
    
    print(f"\n[+] First 10 values as uint64 (unsigned):")
    vals = parse_as_integers(data, 'Q')[:10]
    for offset, val in vals:
        print(f"    Offset {offset:4d}: {val:20d} (0x{val:016x})")
    
    # Look for "suspicious" values
    print(f"\n[+] Searching for potential plaintext values...")
    print(f"    (Looking for values between 1M and 10^15)")
    candidates = find_suspicious_values(data)
    
    if candidates:
        print(f"    Found {len(candidates)} candidates:")
        for offset, val in candidates[:20]:  # Show first 20
            print(f"    Offset {offset:6d}: {val:20d}")
    else:
        print("    No obvious candidates found")
    
    return candidates

def compare_files(data_a: bytes, data_b: bytes):
    """Compare two ciphertext files"""
    print(f"\n{'='*60}")
    print("Comparing a.ct and b.ct")
    print(f"{'='*60}")
    
    min_len = min(len(data_a), len(data_b))
    differences = sum(1 for i in range(min_len) if data_a[i] != data_b[i])
    
    print(f"\n[+] Size comparison:")
    print(f"    a.ct: {len(data_a)} bytes")
    print(f"    b.ct: {len(data_b)} bytes")
    print(f"    Difference: {abs(len(data_a) - len(data_b))} bytes")
    
    print(f"\n[+] Byte-level differences:")
    print(f"    Different bytes: {differences}/{min_len}")
    print(f"    Similarity: {(1 - differences/min_len)*100:.2f}%")

def xor_analysis(data_a: bytes, data_b: bytes):
    """XOR the two ciphertexts (malleability attack)"""
    print(f"\n{'='*60}")
    print("XOR Analysis (Malleability Attack)")
    print(f"{'='*60}")
    
    min_len = min(len(data_a), len(data_b))
    xor_data = bytes(a ^ b for a, b in zip(data_a[:min_len], data_b[:min_len]))
    
    print(f"\n[+] XOR result first 64 bytes (hex):")
    print("   ", xor_data[:64].hex())
    
    # Check if XOR has structure
    zeros = sum(1 for b in xor_data if b == 0)
    ones = sum(1 for b in xor_data if b == 255)
    
    print(f"\n[+] XOR statistics:")
    print(f"    Zeros: {zeros} ({zeros/len(xor_data)*100:.2f}%)")
    print(f"    Ones (255): {ones} ({ones/len(xor_data)*100:.2f}%)")
    
    # Parse XOR as integers
    print(f"\n[+] XOR as int64 values:")
    vals = parse_as_integers(xor_data, 'q')[:10]
    for offset, val in vals:
        print(f"    Offset {offset:4d}: {val:20d}")

def main():
    print("="*60)
    print("PVAC-HFHE Bounty Challenge Analyzer")
    print("Target: $3,333 USDT")
    print("="*60)
    
    # Load files
    a_data = read_file('a.ct')
    b_data = read_file('b.ct')
    
    # Analyze each file
    candidates_a = analyze_structure(a_data, 'a.ct')
    candidates_b = analyze_structure(b_data, 'b.ct')
    
    # Compare files
    compare_files(a_data, b_data)
    
    # XOR analysis
    xor_analysis(a_data, b_data)

    # Optional: analyze sum.ct if present
    sum_candidates = []
    try:
        with open('sum.ct', 'rb') as _:
            sum_data = read_file('sum.ct')
            sum_candidates = analyze_structure(sum_data, 'sum.ct')
    except FileNotFoundError:
        pass
    
    # Summary
    print(f"\n{'='*60}")
    print("ATTACK RECOMMENDATIONS")
    print(f"{'='*60}")
    
    print("\n[!] Based on the hint: 'answer is a 64-bit int, not a small number'")
    print("[!] Your observation: 'they parse bytes as int16/int32/int64'")
    print()
    print("Try these attacks:")
    print("  1. Check the candidate values found above - do any look like plaintexts?")
    print("  2. If you found values in both files, try adding them")
    print("  3. Look at the file structure - is there a header/metadata section?")
    print("  4. Try other integer interpretations at different offsets")
    print("  5. Analyze the params.json and pk.bin files")
    print("  6. Use the provided add.cpp to generate sum ciphertext and analyze it")
    print()
    
    if candidates_a and candidates_b:
        print("[*] POTENTIAL FINDINGS:")
        print(f"    Found {len(candidates_a)} candidates in a.ct")
        print(f"    Found {len(candidates_b)} candidates in b.ct")
        print()
        print("    Try adding pairs:")
        for (off_a, val_a), (off_b, val_b) in zip(candidates_a[:5], candidates_b[:5]):
            print(f"    {val_a} + {val_b} = {val_a + val_b}")

    # Cross-match against sum.ct if available
    if sum_candidates:
        print()
        print("[*] Cross-matching candidate sums with sum.ct candidates:")
        set_a = [v for _, v in candidates_a]
        set_b = [v for _, v in candidates_b]
        sums = set()
        for va in set_a:
            for vb in set_b:
                sums.add(va + vb)
        matches = [(off_s, val_s) for off_s, val_s in sum_candidates if val_s in sums]
        if matches:
            print(f"    Found {len(matches)} matches:")
            for off_s, val_s in matches[:10]:
                print(f"    sum.ct offset {off_s}: {val_s}")
        else:
            print("    No direct matches found. Try broader interpretation or offsets.")

if __name__ == '__main__':
    main()