# Insight.py

## Overview

**Insight.py** is a Python script designed to perform initial fact-finding for suspicious files. The script analyzes a given file, extracting various indicators.

## Features

- Uses regex patterns to identify and extract IP addresses, URLs, domains, and emails from the file content.
- Command-line strings are checked against the file content to identify potential command executions.
- Search for the file on VirusTotal and upload it if not found.
- Run FLARE Obfuscated String Solver(FLOSS) to extract obfuscated strings.
- Match YARA rules against the file.
- Report embedded file types and structures.
- If the input file is a PE (Portable Executable) file, the script extracts compile time, entry point, image base, and section information.
- Provides detailed file information including hash values (MD5, SHA256), and file entropy.

## Dependencies

Install the required dependencies using `pip`:

```
pip install -r requirements.txt
```
## Usage

```
python insight.py <input_file> <output_file> [options]
```
### Options

- `-o`, `--offline`: Disables VirusTotal search/upload.
- `-u`, `--upload`: Uploads sample to VirusTotal if the sample is not found in their database. VirusTotal has an upload limit of 650 MB.
- `-b`, `--browser`: Automatically opens VirusTotal page for the sample in your web browser.
- `-f`, `--floss`: Run floss.exe on the input file.
- `-F`, `--Force`: Forces the script to process files >650 MB. This will likely take a long time.
- `-y`, `--yara`: Path to YARA rules file for matching.

### Example

```
python insight.py suspicious_file.exe report.txt -u -b -f -y my_rules.yar
```

### VirusTotal API Key

Replace `<VirusTotal API Key Here>` in the script with your VirusTotal API key.
