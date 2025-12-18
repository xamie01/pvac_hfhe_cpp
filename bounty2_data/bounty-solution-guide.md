# How to Recognize the Bounty Solution

## What You're Looking For

### **The Answer Format**
The answer is a **single 64-bit integer** (as stated in the hint). This means:
- It's a number between 0 and 2^64-1 (or -2^63 to 2^63-1 if signed)
- It's NOT a small number (so probably > 1,000,000)
- It represents the sum: **plaintext_a + plaintext_b**

### **Example Success Case**

Based on the example code from the repository:
```cpp
Cipher a = enc_value(pk, sk, 42);
Cipher b = enc_value(pk, sk, 17);
Cipher sum = ct_add(pk, a, b); // 42 + 17 = 59
```

For your bounty, if:
- `a.ct` encrypts value X
- `b.ct` encrypts value Y
- Then you need to find: **X + Y**

## How You'll Know You've Found It

### ✅ Recognition Criteria

1. **It's a valid 64-bit integer**
   - Can be represented as a standard int64 or uint64
   - Not corrupted/garbage data
   - Should make sense as a number

2. **It appears in a meaningful way**
   - Extracted from ciphertext structure
   - Derived from a vulnerability/leak
   - NOT random guessing

3. **You can explain HOW you got it**
   - Through format analysis
   - Via homomorphic property exploitation
   - From verification value leak
   - From encoding vulnerability

### 🔍 Where to Look

Based on the "two points" hint and your observation about int parsing:

#### **Point 1: Direct Encoding Leak**
The plaintexts might be directly encoded in the ciphertext structure:

```python
# Example: Reading ciphertext as different integer types
import struct

with open('a.ct', 'rb') as f:
    data = f.read()

# Try reading as int64 at different positions
for offset in range(0, min(len(data), 1000), 8):
    if offset + 8 <= len(data):
        value = struct.unpack('<q', data[offset:offset+8])[0]  # signed int64
        # or
        value = struct.unpack('<Q', data[offset:offset+8])[0]  # unsigned int64
        
        # Look for values that seem "reasonable" as plaintexts
        if 1000000 < value < 2**60:  # Not too small, not maxed out
            print(f"Offset {offset}: {value}")
```

#### **Point 2: Verification Value Leak**
The system claims to be "publicly verifiable" - this might mean verification values are embedded:

```python
# Look for patterns that might be verification tags
# These could be hashes, checksums, or even the plaintext itself!

# Check file structure
print(f"File size: {len(data)} bytes")
print(f"First 64 bytes (hex): {data[:64].hex()}")
print(f"Last 64 bytes (hex): {data[-64:].hex()}")

# Look for recognizable structure (headers, tags, etc.)
```

### 🎯 Validation Steps

Once you think you have the answer (let's call it `N`):

1. **Sanity Check**
   ```python
   # Is it in valid range?
   assert 0 < N < 2**64, "Must be 64-bit integer"
   
   # Is it "not a small number" as hinted?
   assert N > 100000, "Hint says not small"
   ```

2. **Try Both Ciphertexts**
   - Can you extract similar values from both `a.ct` and `b.ct`?
   - Do they look reasonable (e.g., one might be ~billion, other ~million)?

3. **Homomorphic Addition Check**
   - If you can perform `ct_add(pk, a, b)` using the provided `add.cpp`
   - Does analyzing the result confirm your extracted values?

## What the Submission Looks Like

### **Winning Submission Format**

When you solve it, you'll submit to GitHub Issues with:

```markdown
Title: [BOUNTY] Solution for mini-bounty challenge v2

## The Answer
The sum of the two plaintexts is: **[YOUR_NUMBER_HERE]**

## How I Found It

### Vulnerability Discovered
[Describe the vulnerability - e.g.:]
- The encryption function directly embeds the plaintext as int64 at offset X
- Verification values leak information about plaintexts
- Homomorphic addition reveals structure
- etc.

### Attack Method
1. Step-by-step explanation
2. Code used for extraction
3. Why this vulnerability exists

### Evidence
- Screenshots/output showing the extraction
- Code that reproduces the finding
- Analysis of both a.ct and b.ct

## Impact
This vulnerability allows anyone to extract plaintexts from ciphertexts without
the secret key, completely breaking the encryption scheme.
```

### **What Makes a VALID Submission**

✅ **VALID**:
- You provide the correct sum (the number)
- You explain the vulnerability clearly
- You show working code/methodology
- You're the first to submit

❌ **INVALID**:
- Just guessing numbers
- No explanation of method
- Can't reproduce the finding
- Someone else already submitted

## Quick Attack Checklist

Try these in order:

- [ ] **Parse as int64**: Look at both files as arrays of int64 values
- [ ] **Check file headers**: First/last 64-128 bytes often contain metadata
- [ ] **Analyze file structure**: Are there distinct sections? Headers? Tags?
- [ ] **Run homomorphic addition**: Use provided `add.cpp` to see sum ciphertext
- [ ] **Compare all three files**: a.ct, b.ct, and sum.ct (if you generate it)
- [ ] **Look for repeated patterns**: Encryption might be deterministic
- [ ] **Check public key**: Does pk.bin leak information?
- [ ] **Low entropy regions**: Parts of ciphertext with suspiciously low randomness
- [ ] **XOR attack**: Try XORing the two ciphertexts
- [ ] **Modular arithmetic**: Remember p = 2^127 - 1, check if values mod p

## Example Attack Script

```python
#!/usr/bin/env python3
import struct
import json

def analyze_ciphertext(filename):
    with open(filename, 'rb') as f:
        data = f.read()
    
    print(f"\n=== Analyzing {filename} ===")
    print(f"Size: {len(data)} bytes")
    
    # Try int64 interpretation
    print("\n[*] Trying as int64 array:")
    for i in range(min(10, len(data)//8)):
        offset = i * 8
        val_signed = struct.unpack('<q', data[offset:offset+8])[0]
        val_unsigned = struct.unpack('<Q', data[offset:offset+8])[0]
        print(f"  [{i}] signed: {val_signed:20d} | unsigned: {val_unsigned}")
    
    # Check for suspicious values
    print("\n[*] Looking for 'reasonable' plaintext-sized values:")
    for offset in range(0, len(data)-8, 8):
        val = struct.unpack('<Q', data[offset:offset+8])[0]
        # Look for values that could be plaintexts (not too small, not random-looking)
        if 1_000_000 < val < 10**15:
            print(f"  Offset {offset}: {val}")
    
    return data

# Load files
a_data = analyze_ciphertext('a.ct')
b_data = analyze_ciphertext('b.ct')

print("\n[*] If you found suspicious values, try adding them!")
```

## Final Tips

1. **The hint is crucial**: "answer is a 64-bit int, not a small number"
   - This means you should be able to extract it as int64
   - It's probably in the millions to billions range

2. **"Two points" to uncover**:
   - One point is likely the encoding vulnerability
   - Second point might be verification/structural leak

3. **Your observation about int16/int32/int64 parsing**:
   - They're TELLING you plaintexts are parsed as ints
   - This suggests the encoding is straightforward (not heavily obfuscated)

4. **Test your theory**:
   - Once you extract potential values from a.ct and b.ct
   - Add them together - does the sum make sense?
   - Can you verify it somehow?

The answer will be obvious once you find the right vulnerability. You'll extract two numbers, add them, and that sum is your answer!