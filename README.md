# Kernel Module Integrity Monitor (KMIM)

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![Platform: Linux](https://img.shields.io/badge/platform-Linux-lightgrey.svg)](https://www.kernel.org/)

A sophisticated security tool designed to monitor and verify the integrity of kernel modules in Linux systems. KMIM helps detect potential rootkits, malicious kernel modules, and supply chain tampering attempts through continuous monitoring and verification with a rich, color-coded command-line interface.

## 🚀 Features

### 🔒 **Enhanced Security Monitoring**
- **Comprehensive Baseline Management**: Create trusted snapshots of kernel module states
- **Real-time Integrity Scanning**: Detect unauthorized modifications to kernel modules
- **Syscall Table Monitoring**: Monitor 468+ x64 syscalls for integrity
- **Hidden Module Detection**: Identify modules not present in baseline
- **Cryptographic Verification**: SHA256 hash-based integrity checking

### 🎨 **Professional User Experience**
- **Rich Color-coded CLI**: Professional interface with status-based color coding
- **Dual Output Modes**: Simple text + detailed Rich tables
- **Enhanced Error Handling**: Clear, actionable error messages
- **Comprehensive Help System**: Built-in documentation and examples

### 🔧 **Advanced Analysis**
- **Compiler Detection**: Extract and verify compiler information (GCC version, etc.)
- **ELF Section Analysis**: Detailed analysis of module sections (.text, .data, .rodata)
- **Module Metadata**: Complete module information including paths and addresses

## Requirements

- Linux operating system
- Python 3.8 or higher
- Root privileges for module inspection
- Required Python packages (see requirements.txt)

## Installation

1. Install system dependencies:
```bash
sudo apt-get update
sudo apt-get install -y python3-dev python3-pip
```

2. Install KMIM:
```bash
# Clone the repository
git clone https://github.com/hprcse/kmim.git
cd kmim

# Install Python dependencies
pip install -r requirements.txt

# Install KMIM
sudo python setup.py install
```

## Usage

### Creating a Baseline

Create a snapshot of the current kernel module state:
```bash
sudo kmim baseline kmim_baseline.json
```

**Enhanced Output:**
```
[OK] Captured baseline of 127 modules, 468 syscall addresses
Saved to kmim_baseline.json
Baseline created successfully
Modules captured: 127
Syscalls captured: 468
```

This command:
- Identifies all loaded kernel modules
- Calculates SHA256 hashes
- Records module metadata
- **NEW**: Captures syscall table addresses
- **NEW**: Extracts compiler information
- **NEW**: Records ELF section details
- Saves everything to a JSON file

### Scanning for Changes

Compare current state against a baseline:
```bash
sudo kmim scan kmim_baseline.json
```

**Enhanced Output:**
```
[INFO] All modules match baseline
[INFO] No hidden modules
Summary: 127 OK, 0 Suspicious

        Scan Results         
┏━━━━━━━━┳━━━━━━━━┳━━━━━━━━━┓
┃ Module ┃ Status ┃ Details ┃
┡━━━━━━━━╇━━━━━━━━╇━━━━━━━━━┩
│ nvidia │ OK     │         │
└────────┴────────┴─────────┘
```

The scan will detect:
- New modules (hidden modules)
- Missing modules
- Modified modules
- Address changes
- **NEW**: Color-coded status indicators
- **NEW**: Both simple text and rich table output

### Inspecting Modules

View detailed information about a specific module:
```bash
sudo kmim show nvidia
```

**Enhanced Output:**
```
Module: nvidia
Size: 54308864
Addr: 0xffffffffc0000000
Hash: sha256:70c827b...
Compiler: GCC 12.2
ELF Sections: .text, .data, .rodata

                  Module: nvidia                   
┏━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┓
┃ Property     ┃ Value                              ┃
┡━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━┩
│ Size         │ 54308864                           │
│ Hash (full)  │ 70c827b7b46eceebd8c087ab926d698c... │
│ Compiler     │ GCC 12.2                           │
└──────────────┴────────────────────────────────────┘
```

Shows:
- Module size
- Load address
- SHA256 hash (both full and truncated)
- **NEW**: Compiler information
- **NEW**: ELF sections
- File path
- **NEW**: Dual output format (simple + rich table)

### Monitoring Syscalls (NEW)

View syscall table addresses:
```bash
sudo kmim syscalls --limit 10
```

**Enhanced Output:**
```
Syscall Addresses (468 total):
__x64_sys_read: ffffffffa940c3e0
__x64_sys_write: ffffffffa945a8e0
... and 458 more

    Syscall Addresses (first 10)     
┏━━━━━━━━━━━━━━━━┳━━━━━━━━━━━━━━━━━━┓
┃ Syscall Name   ┃ Address          ┃
┡━━━━━━━━━━━━━━━━╇━━━━━━━━━━━━━━━━━━┩
│ __x64_sys_read │ ffffffffa940c3e0 │
└────────────────┴──────────────────┘
```

Features:
- **NEW**: Lists all detected syscalls
- **NEW**: Shows memory addresses
- **NEW**: Configurable output limit
- **NEW**: Color-coded display

## Color Coding System

KMIM features a professional color-coded interface:

- 🟢 **Green**: Success messages, OK status, info notifications
- 🔵 **Blue**: Metadata, counts, summaries, file paths  
- 🟡 **Yellow**: Warnings, syscall names, memory addresses
- 🔴 **Red**: Errors, modified modules, critical issues
- 🟣 **Magenta**: Hash values and cryptographic data
- 🔵 **Cyan**: Property labels, headers, field names
- ⚪ **White**: General data and content
- 🔸 **Dim**: Less important information

## Command Reference

Get general help:
```bash
kmim --help
```

Available commands:
- `baseline` - Create module baseline
- `scan` - Compare against baseline  
- `show` - Display module details
- `syscalls` - Show syscall addresses *(NEW)*

Get command-specific help:
```bash
kmim baseline --help
kmim scan --help
kmim show --help
kmim syscalls --help
```

Shows:
- Module size
- Load address
- SHA256 hash
- File path

## Project Structure

```
.
├── ebpf/               # Kernel module monitoring code
│   └── kmim.bpf.c     # Core monitoring implementation
├── cli/               # Command-line interface
│   ├── __init__.py    # Package initialization
│   ├── kmim.py        # Main CLI implementation (ENHANCED)
│   └── utils.py       # Helper functions (ENHANCED)
├── docs/              # Documentation
│   ├── kmim.1        # Man page (UPDATED)
│   └── REPORT.md     # Design documentation (UPDATED)
├── tests/            # Test suite
├── README.md         # This file (UPDATED)
├── requirements.txt  # Python dependencies
└── setup.py         # Installation configuration
```

## Enhanced Features Summary

### ✅ **New Commands**
- `syscalls` - Monitor syscall table integrity

### ✅ **Enhanced Output**
- Color-coded status indicators
- Dual display modes (simple + rich tables)
- Professional formatting with borders
- Enhanced error messages

### ✅ **Additional Data Capture**
- Syscall table addresses (468+ syscalls)
- Compiler information extraction
- ELF section details
- Hidden module detection

### ✅ **Improved User Experience**
- Rich color coding system
- Better help documentation
- Clear status messages
- Professional CLI appearance

## Security Considerations

### Access Control
- Root privileges required for module inspection
- Baseline files should be protected
- Regular integrity checks recommended

### Best Practices
- Store baselines securely with proper file permissions
- Monitor scan results regularly and investigate anomalies
- Update baselines after legitimate system updates
- Investigate unexpected modifications immediately
- **NEW**: Monitor syscall table integrity regularly
- **NEW**: Use color-coded output for quick visual assessment
- **NEW**: Leverage both simple and detailed output modes

### Limitations
- Cannot prevent module tampering (detection only)
- Detects but doesn't block changes
- Requires trusted baseline for comparison
- False positives possible during legitimate updates
- **NOTE**: Enhanced detection reduces false positives

## Command Line Help

Get general help:
```bash
kmim --help
```

Get command-specific help:
```bash
kmim baseline --help
kmim scan --help
kmim show --help
```

## Contributing

We welcome contributions! Please follow these steps:

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/improvement`)
3. Make your changes
4. Run tests (`python -m pytest`)
5. Commit your changes (`git commit -am 'Add improvement'`)
6. Push to the branch (`git push origin feature/improvement`)
7. Create a Pull Request

## License

This project is licensed under the MIT License. See the LICENSE file for details.

## Authors

Nimisha Thallapally

## Acknowledgments

- Linux Kernel Module Documentation
- Python argparse library
- Rich library for CLI formatting
- Software Security Lab team members
