# Complete Setup Guide for Bounty Challenge

## Python Setup (Recommended)

### ✅ Good News: You Need Almost Nothing!

The analysis script I created uses **only Python standard library** - no external packages required.

### Installation Steps

#### 1. Check Python Version
```bash
python3 --version
# You need Python 3.6 or later
```

If you don't have Python:
- **Ubuntu/Debian**: `sudo apt install python3`
- **macOS**: `brew install python3` or download from python.org
- **Windows**: Download from [python.org](https://www.python.org/downloads/)

#### 2. That's It!

The script uses only built-in modules:
- `struct` - binary data parsing (built-in)
- `sys` - system utilities (built-in)
- `pathlib` - file paths (built-in)
- `typing` - type hints (built-in)

### Optional: Enhanced Analysis Tools

If you want more advanced analysis, you can install these:

```bash
# Create a virtual environment (recommended)
python3 -m venv bounty-env
source bounty-env/bin/activate  # On Windows: bounty-env\Scripts\activate

# Optional packages for advanced analysis
pip install numpy          # For numerical operations
pip install matplotlib     # For visualizing data
pip install scipy          # For statistical analysis
```

### Running the Analysis

```bash
# 1. Download the files from GitHub
wget https://github.com/octra-labs/pvac_hfhe_cpp/raw/main/bounty2_data/a.ct
wget https://github.com/octra-labs/pvac_hfhe_cpp/raw/main/bounty2_data/b.ct
wget https://github.com/octra-labs/pvac_hfhe_cpp/raw/main/bounty2_data/pk.bin
wget https://github.com/octra-labs/pvac_hfhe_cpp/raw/main/bounty2_data/params.json

# 2. Save the Python script (from the artifact above) as bounty_analyzer.py

# 3. Run it
python3 bounty_analyzer.py
```

---

## JavaScript/Node.js Setup

If you prefer JavaScript (for web-based analysis or Node.js):

### Installation Steps

#### 1. Install Node.js
```bash
# Check if you have Node.js
node --version
# You need Node.js 14 or later
```

If you don't have Node.js:
- **Ubuntu/Debian**: `sudo apt install nodejs npm`
- **macOS**: `brew install node`
- **Windows**: Download from [nodejs.org](https://nodejs.org/)

#### 2. No External Packages Needed!

Node.js built-in modules are sufficient:
- `fs` - file system operations (built-in)
- `Buffer` - binary data handling (built-in)

### JavaScript Analysis Script

```javascript
// Save as bounty_analyzer.js
const fs = require('fs');

function analyzeFile(filename) {
    console.log(`\n${'='.repeat(60)}`);
    console.log(`Analyzing ${filename}`);
    console.log('='.repeat(60));
    
    const data = fs.readFileSync(filename);
    console.log(`\n[+] File size: ${data.length} bytes (${(data.length/1024).toFixed(2)} KB)`);
    
    // First 64 bytes
    console.log(`\n[+] First 64 bytes (hex):`);
    console.log('   ', data.slice(0, 64).toString('hex'));
    
    // Parse as int64
    console.log(`\n[+] First 10 values as int64 (little-endian):`);
    for (let i = 0; i < Math.min(80, data.length - 8); i += 8) {
        const val = data.readBigInt64LE(i);
        console.log(`    Offset ${i.toString().padStart(4)}: ${val.toString().padStart(20)}`);
    }
    
    // Parse as uint64
    console.log(`\n[+] First 10 values as uint64:`);
    for (let i = 0; i < Math.min(80, data.length - 8); i += 8) {
        const val = data.readBigUInt64LE(i);
        console.log(`    Offset ${i.toString().padStart(4)}: ${val.toString().padStart(20)}`);
    }
    
    // Find suspicious values
    console.log(`\n[+] Searching for potential plaintext values...`);
    const candidates = [];
    for (let i = 0; i < data.length - 8; i += 8) {
        const val = data.readBigUInt64LE(i);
        if (val > 1_000_000n && val < 10n ** 15n) {
            candidates.push({ offset: i, value: val });
        }
    }
    
    if (candidates.length > 0) {
        console.log(`    Found ${candidates.length} candidates:`);
        candidates.slice(0, 20).forEach(c => {
            console.log(`    Offset ${c.offset.toString().padStart(6)}: ${c.value.toString().padStart(20)}`);
        });
    } else {
        console.log('    No obvious candidates found');
    }
    
    return { data, candidates };
}

function xorAnalysis(data_a, data_b) {
    console.log(`\n${'='.repeat(60)}`);
    console.log('XOR Analysis');
    console.log('='.repeat(60));
    
    const minLen = Math.min(data_a.length, data_b.length);
    const xorData = Buffer.alloc(minLen);
    
    for (let i = 0; i < minLen; i++) {
        xorData[i] = data_a[i] ^ data_b[i];
    }
    
    console.log(`\n[+] XOR result first 64 bytes (hex):`);
    console.log('   ', xorData.slice(0, 64).toString('hex'));
    
    console.log(`\n[+] XOR as int64 values:`);
    for (let i = 0; i < Math.min(80, xorData.length - 8); i += 8) {
        const val = xorData.readBigInt64LE(i);
        console.log(`    Offset ${i.toString().padStart(4)}: ${val.toString().padStart(20)}`);
    }
}

// Main execution
console.log('='.repeat(60));
console.log('PVAC-HFHE Bounty Challenge Analyzer (JavaScript)');
console.log('='.repeat(60));

const result_a = analyzeFile('a.ct');
const result_b = analyzeFile('b.ct');

xorAnalysis(result_a.data, result_b.data);

console.log(`\n${'='.repeat(60)}`);
console.log('SUMMARY');
console.log('='.repeat(60));

if (result_a.candidates.length > 0 && result_b.candidates.length > 0) {
    console.log('\n[*] Found candidates in both files!');
    console.log('    Try adding pairs:');
    for (let i = 0; i < Math.min(5, result_a.candidates.length, result_b.candidates.length); i++) {
        const sum = result_a.candidates[i].value + result_b.candidates[i].value;
        console.log(`    ${result_a.candidates[i].value} + ${result_b.candidates[i].value} = ${sum}`);
    }
}
```

Run it:
```bash
node bounty_analyzer.js
```

---

## Browser-Based Analysis

You can also analyze files directly in the browser using the React artifact I created:

### No Installation Required!

1. The artifact is already available in Claude's interface
2. Just upload your downloaded a.ct and b.ct files
3. Click "Analyze Files"

### To Use Files in Browser:

The React artifact I created uses the FileReader API - just:
1. Download a.ct and b.ct from GitHub
2. Upload them in the artifact interface
3. View the analysis results

---

## C++ Tools (For Running Their Code)

If you want to compile and run the original C++ code:

### Installation

```bash
# Ubuntu/Debian
sudo apt install build-essential g++ make

# macOS
xcode-select --install
# or
brew install gcc

# Windows
# Install MinGW-w64 or Visual Studio 2019+
```

### Compile and Run Examples

```bash
# Clone the repository
git clone https://github.com/octra-labs/pvac_hfhe_cpp.git
cd pvac_hfhe_cpp

# Compile the addition example
g++ -std=c++17 -O2 -march=native -I./include tests/add.cpp -o add

# Run it (this will try to add a.ct and b.ct)
./add
```

---

## Recommended Workflow

### 🥇 Best Approach: Python

```bash
# 1. Download files
cd ~/bounty-challenge  # or wherever you want
wget https://github.com/octra-labs/pvac_hfhe_cpp/raw/main/bounty2_data/a.ct
wget https://github.com/octra-labs/pvac_hfhe_cpp/raw/main/bounty2_data/b.ct

# 2. Run Python analysis (no installs needed!)
python3 bounty_analyzer.py

# 3. Try manual exploration
python3
>>> import struct
>>> with open('a.ct', 'rb') as f:
...     data = f.read()
>>> # Explore interactively
```

### 🥈 Alternative: JavaScript

```bash
# 1. Download files (same as above)

# 2. Run Node.js analysis (no npm packages needed!)
node bounty_analyzer.js
```

### 🥉 Browser Option

Use the React artifact - just upload files, no installation required!

---

## Additional Useful Tools (Optional)

### Hex Editors (For Manual Inspection)

```bash
# Command line hex viewer
hexdump -C a.ct | head -n 20
xxd a.ct | head -n 20

# Or install a GUI hex editor
sudo apt install ghex        # Linux
brew install --cask hex-fiend  # macOS
# Windows: HxD (free download)
```

### Binary Diff Tools

```bash
# Compare two binary files
cmp -l a.ct b.ct | head -n 20

# Visual diff
sudo apt install vbindiff
vbindiff a.ct b.ct
```

---

## Quick Start Script

```bash
#!/bin/bash
# Save as setup.sh and run: bash setup.sh

echo "Setting up bounty challenge environment..."

# Create working directory
mkdir -p bounty-challenge
cd bounty-challenge

# Download files
echo "Downloading challenge files..."
wget -q https://github.com/octra-labs/pvac_hfhe_cpp/raw/main/bounty2_data/a.ct
wget -q https://github.com/octra-labs/pvac_hfhe_cpp/raw/main/bounty2_data/b.ct
wget -q https://github.com/octra-labs/pvac_hfhe_cpp/raw/main/bounty2_data/pk.bin
wget -q https://github.com/octra-labs/pvac_hfhe_cpp/raw/main/bounty2_data/params.json

# Check Python
if command -v python3 &> /dev/null; then
    echo "✓ Python3 found: $(python3 --version)"
else
    echo "✗ Python3 not found - please install it"
fi

# Check Node.js
if command -v node &> /dev/null; then
    echo "✓ Node.js found: $(node --version)"
else
    echo "✗ Node.js not found (optional)"
fi

echo ""
echo "Setup complete! Files downloaded:"
ls -lh *.ct *.bin *.json

echo ""
echo "Next steps:"
echo "1. Save the Python analyzer script as bounty_analyzer.py"
echo "2. Run: python3 bounty_analyzer.py"
```

---

## Summary: What You Actually Need

### Minimal Setup (Python):
```bash
✓ Python 3.6+  (usually pre-installed)
✓ No pip packages required
✓ Download 2 files (a.ct, b.ct)
✓ Run the script
```

### That's literally it! 

No complex dependencies, no package managers, no configuration. Just Python (which you probably already have) and the challenge files.