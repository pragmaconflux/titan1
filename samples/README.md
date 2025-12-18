# Sample Test Files

This directory contains simple test files to verify your Titan Decoder installation.

## Files

### base64_sample.txt
Simple Base64 encoded string: "Hello from Titan Decoder!"

**Test:**
```bash
titan-decoder --file base64_sample.txt --progress
```

**Expected output:**
- 2 nodes generated
- Decoded text visible in content_preview
- IOCs: none

### gzip_sample.gz
Gzipcompressed text string.

**Test:**
```bash
titan-decoder --file gzip_sample.gz --progress
```

**Expected output:**
- 2 nodes generated  
- Gzip decoder used
- Decoded text in preview

### nested_encoding.txt
Multiple layers of Base64 encoding (3 levels deep).

**Test:**
```bash
titan-decoder --file nested_encoding.txt --max-depth 5 --progress
```

**Expected output:**
- 4+ nodes generated
- Multiple Base64 decode operations
- Detection rule "TITAN-001" (Deep Base64 Nesting) may trigger

## Usage

Run all samples:
```bash
for file in *.txt *.gz; do
  echo "Testing $file..."
  titan-decoder --file "$file" --out "reports/${file}_report.json"
done
```

Batch processing:
```bash
cd ..
titan-decoder --batch samples --batch-pattern "*" --out samples/reports
```

## Creating Your Own Samples

**Nested Base64:**
```bash
echo "secret" | base64 | base64 | base64 > nested.txt
```

**Gzip:**
```bash
echo "data" | gzip > data.gz
```

**Hex:**
```bash
echo "hello" | xxd -p > hex_sample.txt
```
