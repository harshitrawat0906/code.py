# Hash Decode Tool

Hash Decode Tool is a terminal-based Python application that attempts to decode various types of hash values (MD5, SHA-1, SHA-256, SHA-384, and SHA-512) by querying multiple online APIs. This tool is helpful for reverse engineering and quickly finding plaintext values of known hash types.

## Features
- **Single Hash Decoding**: Decode a single hash value directly from the command line.
- **File-Based Decoding**: Decode multiple hash values provided in a file.
- **Directory-Based Decoding**: Extract and decode hashes found in files within a specified directory.
- **Multi-Threaded**: Uses threading for faster hash decoding.
- **Supports Multiple Hash Types**: MD5, SHA-1, SHA-256, SHA-384, and SHA-512.

## Requirements
- Python 3.x
- `requests` library for making API requests

To install the `requests` library, run:
```bash
pip install requests
