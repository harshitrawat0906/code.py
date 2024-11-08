#!/usr/bin/env python3

import re
import os
import requests
import argparse
import concurrent.futures

parser = argparse.ArgumentParser(description="Hash Decode Tool - Decodes common hash types via online APIs.")
parser.add_argument('-s', help='Single hash', dest='hash')
parser.add_argument('-f', help='File containing hashes', dest='file')
parser.add_argument('-d', help='Directory containing hashes', dest='dir')
parser.add_argument('-t', help='Number of threads', dest='threads', type=int, default=4)
args = parser.parse_args()

END = '\033[0m'
RED = '\033[91m'
GREEN = '\033[92m'
YELLOW = '\033[93m'
INFO = '\033[94m[?]\033[0m'
BAD = '\033[91m[-]\033[0m'
GOOD = '\033[92m[+]\033[0m'

cwd = os.getcwd()
directory = args.dir
file = args.file
thread_count = args.threads

if directory and directory[-1] == '/':
    directory = directory[:-1]

def decode_alpha(hash_value, hash_type):
    return False

def decode_beta(hash_value, hash_type):
    response = requests.get(f'https://hashtoolkit.com/reverse-hash/?hash={hash_value}').text
    match = re.search(r'/generate-hash/\?text=(.*?)"', response)
    return match.group(1) if match else False

def decode_gamma(hash_value, hash_type):
    response = requests.get(f'https://www.nitrxgen.net/md5db/{hash_value}', verify=False).text
    return response if response else False

def decode_theta(hash_value, hash_type):
    response = requests.get(f'https://md5decrypt.net/Api/api.php?hash={hash_value}&hash_type={hash_type}&email=deanna_abshire@proxymail.eu&code=1152464b80a61728').text
    return response if response else False

print(f'''{YELLOW}
 ____  _   _   ____                        _     
|  _ \| |_| | |  _ \   __ _  __ _  ___ ___| |__  
| | | | __| |_| | | | / _` |/ _` |/ __/ _ \ '_ \ 
| |_| | |_| |_| |_| || (_| | (_| | (_|  __/ |_) |
|____/ \__|\__, |____(_)__, |\__, |\___\___|_.__/  v3.0
           |___/         |_|  |___/
{END}''')

hash_types = {
    32: ("MD5", [decode_gamma, decode_alpha, decode_beta, decode_theta]),
    40: ("SHA1", [decode_alpha, decode_beta, decode_theta]),
    64: ("SHA-256", [decode_alpha, decode_beta, decode_theta]),
    96: ("SHA-384", [decode_alpha, decode_beta, decode_theta]),
    128: ("SHA-512", [decode_alpha, decode_beta, decode_theta])
}

def decode_hash(hash_value):
    result = None
    hash_type, api_list = hash_types.get(len(hash_value), (None, []))
    
    if not hash_type:
        print(f'{BAD} Unsupported hash type for: {hash_value}')
        return None
    
    print(f'{INFO} Decoding hash ({hash_type}): {hash_value}')
    for api in api_list:
        result = api(hash_value, hash_type.lower())
        if result:
            print(f'{GOOD} Decoded: {hash_value} -> {result}')
            return result
    print(f'{BAD} No match found for: {hash_value}')
    return None

def threaded_decode(hash_value):
    result = decode_hash(hash_value)
    if result:
        results[hash_value] = result

def extract_hashes_from_directory(directory):
    os.system(
        f'''grep -Pr "[a-f0-9]{{32}}|[a-f0-9]{{40}}|[a-f0-9]{{64}}|[a-f0-9]{{96}}|[a-f0-9]{{128}}" {directory} --exclude=\*.{{png,jpg,jpeg,mp3,mp4,zip,gz}} | 
        grep -Po "[a-f0-9]{{32}}|[a-f0-9]{{40}}|[a-f0-9]{{64}}|[a-f0-9]{{96}}|[a-f0-9]{{128}}" >> {cwd}/{directory.split('/')[-1]}.txt'''
    )
    print(f'{INFO} Results saved in {directory.split("/")[-1]}.txt')

def extract_and_decode_hashes_from_file(file):
    hashes = set()
    with open(file, 'r') as f:
        for line in f:
            hashes.update(re.findall(r'[a-f0-9]{32}|[a-f0-9]{40}|[a-f0-9]{64}|[a-f0-9]{96}|[a-f0-9]{128}', line))
    
    print(f'{INFO} Found {len(hashes)} hashes in {file}')
    with concurrent.futures.ThreadPoolExecutor(max_workers=thread_count) as executor:
        list(executor.map(threaded_decode, hashes))
    
    with open(f'cracked-{file.split("/")[-1]}', 'w') as f:
        for hash_value, cracked in results.items():
            f.write(f'{hash_value}:{cracked}\n')
    print(f'{INFO} Decoding results saved in cracked-{file.split("/")[-1]}')

results = {}

if directory:
    extract_hashes_from_directory(directory)
elif file:
    extract_and_decode_hashes_from_file(file)
elif args.hash:
    decode_hash(args.hash)
else:
    print(f'{BAD} No input provided. Use -s for single hash, -f for file, or -d for directory.')
