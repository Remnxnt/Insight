#_________________________________________________
#    _____                   _         __       _    
#   _   _|                 (_)       [  |     / |_  
#    | |   _ .--.   .--.   __   .--./)| |--. `| |-' 
#   | |  [ `.-. | ( (`\] [  | / /'`\;| .-. | | |   
# _| |_  | | | |  `'.'.  | | \ \._//| | | | | |,  
#|_____|[___||__][\__) )[___].',__`[___]|__]\__/  
#                           ( ( __))              
#_________________________________________________

apikey = '<VirusTotal API Key Here>'

####################################################
####################################################

import argparse 
def parse_args():
    parser = argparse.ArgumentParser(
        prog='Insight.py',
        description='Performs initial fact finding for your suspicious files.'
    )
    parser.add_argument('input')
    parser.add_argument('output')
    parser.add_argument('-o', '--offline', action='store_true', help='Disables VirusTotal search/upload')
    parser.add_argument('-u', '--upload', action='store_true', help='Uploads sample to VirusTotal if the sample is not found in their database. VirusTotal has an upload limit of 650 MB.')
    parser.add_argument('-b', '--browser', action='store_true', help='Automatically opens VirusTotal page for the sample in your web browser.')
    parser.add_argument('-f', '--floss', action='store_true', help='Run FLARE Obfuscated String Solver on the input file.')
    parser.add_argument('-F', '--Force', action='store_true', help='Forces the script to process files >650 MB. This will likely take a long time.')
    parser.add_argument('-y', '--yara', type=str, help = 'Path to YARA rules file for matching.')
    args = parser.parse_args()

    if args.offline and args.upload:
        print('\nWhy would you do that? --offline and --upload / --browser are mutually exclusive silly goose. Disregarding --upload / --browser.\n')
        args.upload = False

    return args

import re
def compile_regex_patterns():
    return {
        'ip': re.compile(r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'),
        'url': re.compile(r'http[s]?://(?:[a-zA-Z]|[0-9]|[$-_@.&+]|[!*\\(\\),]|(?:%[0-9a-fA-F][0-9a-fA-F]))+'),
        'domain': re.compile(r'\b(?:[a-zA-Z0-9-]+\.)+[a-zA-Z]{2,6}\b'),
        'email': re.compile(r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b')
    }

import math
def entropy(filepath):
    if not os.path.isfile(filepath):
        return 0.0
    
    byte_counts = [0] * 256
    total_bytes = 0
    
    with open(filepath, 'rb') as f:
        while chunk := f.read(8192):
            total_bytes += len(chunk)
            for byte in chunk:
                byte_counts[byte] += 1

    if total_bytes == 0:
        return 0.0
    
    entropy = 0
    for count in byte_counts:
        p_x = count / total_bytes
        if p_x > 0:
            entropy += - p_x * math.log(p_x, 2)
    return entropy

def fnindicators(filepath, patterns):
    indicators = {key: [] for key in patterns}
    with open(filepath, 'r', errors='ignore') as f:
        while chunk := f.read(8192):
            if chunk:
                for key, pattern in patterns.items():
                    if key in indicators:
                        indicators[key].extend(pattern.findall(chunk))
    for key in indicators:
        indicators[key] = list(set(indicators[key]))

    return indicators

def cmdsearch(filepath, cmd_str):
    matches = []
    with open(filepath, 'r', errors='ignore') as f:
        while chunk := f.read(8192):
            for cmd in cmd_str:
                if cmd in chunk:
                    matches.append(cmd)
    return matches

import hashlib
def hashslingingslasher(filepath):
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()
    with open(filepath,'rb') as f:
        while chunk := f.read(8192):
            md5.update(chunk)
            sha256.update(chunk)
    return md5.hexdigest(), sha256.hexdigest()

import magic, os; from pathlib import Path
def finfo(args, cmd_str, patterns):
    m = magic.Magic(mime=True)
    ft = m.from_file(args.input)
    md5, sha256 = hashslingingslasher(args.input)
    fentropy = entropy(args.input)
    fname = os.path.basename(args.input)
    fname2 = Path(args.input).stem
    if args.floss:
        run_floss(args, fname2)
        floss_file_path = f'floss_{fname2}.txt'
        nindicators = fnindicators(floss_file_path, patterns)
        cmdmatch = cmdsearch(floss_file_path, cmd_str)
    else:
        nindicators = fnindicators(args.input, patterns)
        cmdmatch = cmdsearch(args.input, cmd_str)
    return ft, md5, sha256, fentropy, fname, nindicators, cmdmatch

def fsizeconv(fsizeb):
    if fsizeb < 1024:
        return f"{fsizeb}B"
    elif fsizeb < 1024 ** 2:
        return f"{fsizeb / 1024:.2f}KB"
    elif fsizeb < 1024 ** 3:
        return f"{fsizeb / (1024 ** 2):.2f}MB"
    elif fsizeb < 1024 ** 4:
        return f"{fsizeb / (1024 ** 3):.2f}GB"

import datetime, pefile
def pe_info(args):
    try:
        pe = pefile.PE(args.input)
        ctime = datetime.datetime.fromtimestamp(pe.FILE_HEADER.TimeDateStamp).strftime('%Y-%m-%d %H:%M:%S')
        entry = hex(pe.OPTIONAL_HEADER.AddressOfEntryPoint)
        ibase = hex(pe.OPTIONAL_HEADER.ImageBase)
        sections = [(section.Name.decode().strip('\x00'), hex(section.VirtualAddress), hex(section.Misc_VirtualSize)) for section in pe.sections]
        return ctime, entry, ibase, sections    
    except pefile.PEFormatError:
        return None, None, None, None


import yara
def yara_match(file_path, rules_path):
    rules = yara.compile(filepath=rules_path)
    matches = rules.match(file_path)
    return matches

import requests, webbrowser
def virustotal(args, ft, sha256, fsizeb):
    url = f"https://virustotal.com/api/v3/files/{sha256}"
    headers = {
        "accept": "application/json",
        "x-apikey": apikey
    }
    response = requests.get(url=url, headers=headers)
    if response.status_code == 404:
        if args.upload:
            print('Uploading file to VirusTotal')
            if fsizeb > 33554432:
                bupl_url = "https://virustotal.com/api/v3/files/upload_url"
                buplresponse = requests.get(url=bupl_url, headers=headers)
                if buplresponse.status_code == 200:
                    upl_url = buplresponse.json().get("data")
                    files = {"file": (args.input, open(args.input, 'rb'), ft)}
                    upload_response = requests.post(url=upl_url, files=files, headers=headers)
                else:
                    print('Failed to get large upload url from VirusTotal.')
                    return False           
            else:
                upl_url = "https://virustotal.com/api/v3/files"
                files = {"file": (args.input, open(args.input, 'rb'), ft)}
                upload_response = requests.post(url=upl_url, files=files, headers=headers)
            if upload_response.status_code == 200 and args.browser:
                print('Upload to VirusTotal complete.')
                webbrowser.open(f'https://virustotal.com/gui/file/{sha256}')
                return True
        else:
            print('File not found on VirusTotal, and upload not selected. Skipping.')
            return False
    elif response.status_code == 200:
        print('File was successfully found in VirusTotal database.')
        if args.browser:
            webbrowser.open(f'https://virustotal.com/gui/file/{sha256}')
        return True
    elif response.status_code == 401:
        print('Unauthorized, Check API key.')
        return False
    else:
        print(f'{response.status_code}\n')
        print(f'{response}')
        print("Could not connect to VirusTotal. Skipping.")
        return False

def run_floss(args, fname2):
    floss_cmd = f'floss.exe "{args.input}" > floss_{fname2}.txt'
    os.system(floss_cmd)
    print(f"FLOSS output has been saved to floss_{fname2}.txt")

def write_report(args, fname, fsize, md5, sha256, ft, vt, fentropy, nindicators, cmdmatch, dieo, ctime, fentry, fibase, fsections, yara_matches):
    with open(args.output, 'w', encoding='utf-8') as output_file:
        output_file.write(f"Date of Analysis: {datetime.date.today()}\n")
        output_file.write(f'File Name: {fname}\n')
        output_file.write(f'File Size: {fsize}\n')
        output_file.write(f"MD5: {md5}\n")
        output_file.write(f"SHA256: {sha256}\n")
        output_file.write(f"MIME: {ft}\n")
        if vt:
            output_file.write(f'VirusTotal: https://virustotal.com/gui/file/{sha256}\n')
        output_file.write(f'File Entropy: {fentropy:.4f}\n')
        if any(nindicators.values()):
            output_file.write('Network Indicators:\n')
            for key, values in nindicators.items():
                output_file.write(f"    {key}: {', '.join(values) if values else 'None Found'}\n")
        if cmdmatch:
            output_file.write('Command-Line Strings Found:\n')
            output_file.write(f"    {', '.join(cmdmatch)}\n")
        output_file.write('Detect It Easy:\n')
        for detect in dieo['detects']:
            output_file.write(f"    File Type: {detect['filetype']}\n")
            output_file.write(f"    Parent File Part: {detect['parentfilepart']}\n")
            for value in detect['values']:
                output_file.write(f"\n        Name: {value['name']}\n")
                output_file.write(f"        Type: {value['type']}\n")
                output_file.write(f"        Version: {value['version']}\n")
        if ctime:
            output_file.write(f'PE Compile Time: {ctime}\n')
            output_file.write(f'Entry Point: {fentry}\n')
            output_file.write(f'Image Base: {fibase}\n')
            output_file.write('PE Sections:\n')
            for section in fsections:
                output_file.write(f"    Name: {section[0]}, Virtual Address: {section[1]}, Virtual Size: {section[2]}\n")
        if args.yara:
            output_file.write(f"YARA Matches: {'No Matches' if not yara_matches else yara_matches}")
import json, die
def main():
    args = parse_args()
    fsizeb = os.path.getsize(args.input)
    if fsizeb > 681574400:
        if not args.Force:
            raise SystemExit('File too `large, you can try with -F or --Force.')
    cmd_str = [
        'cmd.exe', 'cmd', 'powershell.exe', 'wscript.exe', 'cscript.exe',
        'rundll32.exe', 'regsvr32.exe', '/bin/sh', '/bin/bash', '/bin/ksh', '/bin/zsh',
        '/usr/bin/perl', '/usr/bin/python', '/usr/bin/ruby', '/usr/bin/php', '/usr/bin/expect',
        'java', 'node', 'python', 'perl', 'ruby', 'php', 'rubyw', 'javaw', 'mshta', 'certutil',
        'Shell', 'CreateObject("WScript.Shell")', 'CreateObject("Scripting.FileSystemObject")',
        'eval', 'setTimeout', 'setInterval', 'Function("...")',
        'Invoke-Expression', 'Invoke-Command', 'Invoke-WebRequest', 'Start-Process', 'New-Object', 'IEX',
        'curl', 'wget', 'PsExec', 'RDP', 'SSH'
    ]
    patterns = compile_regex_patterns()
    ft, md5, sha256, fentropy, fname, nindicators, cmdmatch = finfo(args, cmd_str, patterns)
    fsize = fsizeconv(fsizeb)
    ctime, fentry, fibase, fsections = pe_info(args)
    dieostr = die.scan_file(args.input, die.ScanFlags.RESULT_AS_JSON, str(die.database_path/'db'))
    dieo = json.loads(dieostr)
    if args.yara:
        yara_matches = yara_match(args.input, args.yara)  
    else:
        yara_matches = False
    vt = virustotal(args, ft, sha256, fsizeb) if not args.offline else False
    write_report(args, fname, fsize, md5, sha256, ft, vt, fentropy, nindicators, cmdmatch, dieo, ctime, fentry, fibase, fsections, yara_matches)

if __name__ == '__main__':
    main()
