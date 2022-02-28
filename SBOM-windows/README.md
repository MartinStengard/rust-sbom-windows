# Rust projects
## Generate SBOM file for Windows
This project generates a complete SBOM file for a Windows machine. It extract installed programs from:
- WMI query "Win32_Product"
- Key registry "SOFTWARE\Microsoft\Windows\CurrentVersion\Uninstall"
- Key registry "SOFTWARE\WOW6432Node\Microsoft\Windows\CurrentVersion\Uninstall"

Please send me a note on improvements and if you have use of this code.
