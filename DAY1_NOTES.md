# Day 1 Learning Notes

## 1. Cybersecurity
Cybersecurity protects computers, systems, networks, applications, and data from unauthorized access, damage, misuse, and other threats.

## 2. File Analysis
File analysis means examining a file's characteristics and contents to collect evidence about the file.

## 3. Static Analysis
Static analysis examines a file without executing it.

## 4. File Extension
The extension is the part after the final dot in a filename, such as `.pdf`, `.jpg`, or `.exe`. An extension alone does not prove that a file is safe or malicious.

## 5. File Size
The scanner records the file size. Size is useful information but does not by itself determine whether a file is malicious.

## 6. SHA-256
SHA-256 is a cryptographic hash function. It produces a fixed-length hexadecimal digest that can be used as a digital fingerprint for file contents.

## 7. Day 1 Flow
User gives file path
→ scanner reads metadata
→ scanner calculates SHA-256
→ results are displayed

## 8. What Day 1 Does NOT Do
It does not:
- execute files
- remove files
- declare a file malware
- perform antivirus scanning
- connect to external malware databases

Those can be considered in later versions.
