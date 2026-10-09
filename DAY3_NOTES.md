# Day 3 Learning Notes

## Double Extension
A filename such as `invoice.pdf.exe` contains multiple extension-like parts and can be a useful suspicious indicator.

## File Signature / Magic Number
Many formats begin with recognizable bytes. Examples include `%PDF-` for PDF, the PNG header for PNG, common JPEG bytes, `PK` for ZIP-based files, and `MZ` for Windows PE/executable family.

## Extension vs Signature
The extension is what the filename claims. The signature gives evidence about the file format. A mismatch is worth investigating.

## Suspicious Indicators
Day 3 reports possible double extensions, executable/script extensions, extension/signature mismatches, and unknown signatures.

## Flow
File → metadata → extension → double-extension check → signature check → indicators → SHA-256 → report

## Limitation
This is an educational static-analysis tool. It does not replace professional antivirus or malware-analysis systems and does not prove a file safe or malicious.
