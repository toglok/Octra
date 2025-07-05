import os
import base64
import hashlib
import hmac
import base58
import asyncio
import aiohttp
import json
import time
import re
from mnemonic import Mnemonic
from nacl.signing import SigningKey, VerifyKey
from nacl.encoding import RawEncoder
from datetime import datetime
from colorama import init, Fore, Style
from art import text2art
from tqdm import tqdm
import sys

# Initialize colorama for colored output
init(autoreset=True)

# Configuration
ADDRESS_FILE = 'addresses.txt'
WALLET_FILE = 'wallets.txt'
AMOUNT_TO_SEND = 0.01
DEFAULT_RPC = 'https://octra.network'
TX_EXPLORER_URL = 'https://octrascan.io/tx/'
REQUEST_TIMEOUT = 30
MAX_RETRIES = 3
RETRY_DELAY = 2

# Helper functions for wallet generation
def buffer_to_hex(buffer: bytes) -> str:
    return buffer.hex()

def base64_encode(buffer: bytes) -> str:
    return base64.b64encode(buffer).decode('utf-8')

def base58_encode(buffer: bytes) -> str:
    return base58.b58encode(buffer).decode('utf-8')

def generate_entropy(strength: int = 128) -> bytes:
    if strength not in [128, 160, 192, 224, 256]:
        raise ValueError("Strength must be 128, 160, 192, 224 or 256 bits")
    return os.urandom(strength // 8)

def derive_master_key(seed: bytes) -> tuple[bytes, bytes]:
    key = b"Octra seed"
    mac = hmac.new(key, seed, hashlib.sha512).digest()
    master_private_key = mac[:32]
    master_chain_code = mac[32:64]
    return master_private_key, master_chain_code

def create_octra_address(public_key: bytes) -> str:
    hash = hashlib.sha256(public_key).digest()
    base58_hash = base58_encode(hash)
    return "oct" + base58_hash

def verify_address_format(address: str) -> bool:
    if not address.startswith("oct"):
        return False
    base58_alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"
    base58_part = address[3:]
    if not (44 <= len(address) <= 47):
        return False
    return all(char in base58_alphabet for char in base58_part)

async def generate_wallet(index: int) -> dict:
    try:
        entropy = generate_entropy(128)
        await asyncio.sleep(0.2)

        mnemo = Mnemonic("english")
        mnemonic = mnemo.generate(strength=128)
        mnemonic_words = mnemonic.split()
        await asyncio.sleep(0.2)

        seed = mnemo.to_seed(mnemonic)
        await asyncio.sleep(0.2)

        master_private_key, master_chain_code = derive_master_key(seed)
        await asyncio.sleep(0.2)

        signing_key = SigningKey(master_private_key, encoder=RawEncoder)
        private_key = signing_key.encode()
        public_key = signing_key.verify_key.encode()
        await asyncio.sleep(0.2)

        address = create_octra_address(public_key)
        if not verify_address_format(address):
            raise ValueError("Invalid address format generated")
        await asyncio.sleep(0.2)

        test_message = '{"from":"test","to":"test","amount":"1000000","nonce":1}'
        message_bytes = test_message.encode('utf-8')
        signature = signing_key.sign(message_bytes, encoder=RawEncoder).signature
        signature_b64 = base64_encode(signature)
        signature_valid = VerifyKey(public_key, encoder=RawEncoder).verify(message_bytes, signature, encoder=RawEncoder)
        await asyncio.sleep(0.2)

        wallet_data = {
            'mnemonic': mnemonic_words,
            'seed_hex': buffer_to_hex(seed),
            'master_chain_hex': buffer_to_hex(master_chain_code),
            'private_key_hex': buffer_to_hex(private_key),
            'public_key_hex': buffer_to_hex(public_key),
            'private_key_b64': base64_encode(private_key),
            'public_key_b64': base64_encode(public_key),
            'address': address,
            'entropy_hex': buffer_to_hex(entropy),
            'test_message': test_message,
            'test_signature': signature_b64,
            'signature_valid': signature_valid
        }

        content = f"""OCTRA WALLET {index}
{Style.BRIGHT + Fore.CYAN + '=' * 50}

{Fore.RED + 'SECURITY WARNING: KEEP THIS FILE SECURE AND NEVER SHARE YOUR PRIVATE KEY'}

Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}
Address Format: oct + Base58(SHA256(pubkey))

{Fore.GREEN}Mnemonic: {' '.join(wallet_data['mnemonic'])}
{Fore.YELLOW}Private Key (Hex): {wallet_data['private_key_hex']}
{Fore.YELLOW}Private Key (B64): {wallet_data['private_key_b64']}
{Fore.CYAN}Public Key (Hex): {wallet_data['public_key_hex']}
{Fore.CYAN}Public Key (B64): {wallet_data['public_key_b64']}
{Fore.MAGENTA}Address: {wallet_data['address']}

{Fore.BLUE}Technical Details:
Entropy: {wallet_data['entropy_hex']}
Seed: {wallet_data['seed_hex']}
Master Chain Code: {wallet_data['master_chain_hex']}
Signature Algorithm: Ed25519
Test Message: {wallet_data['test_message']}
Test Signature (B64): {wallet_data['test_signature']}
Signature Valid: {wallet_data['signature_valid']}
{Style.BRIGHT + Fore.CYAN + '=' * 50}

"""
        with open(WALLET_FILE, 'a', encoding='utf-8') as f:
            f.write(content)

        with open(ADDRESS_FILE, 'a', encoding='utf-8') as f:
            f.write(f"{wallet_data['address']}\n")
        await asyncio.sleep(0.2)

        return wallet_data

    except Exception as e:
        print(f"{Fore.RED}Error with wallet {index}: {str(e)}")
        raise

async def generate_multiple_wallets(count: int):
    semaphore = asyncio.Semaphore(2)
    successful_wallets = 0

    async def process_wallet(index):
        nonlocal successful_wallets
        async with semaphore:
            try:
                await generate_wallet(index)
                successful_wallets += 1
            except Exception:
                pass

    print(f"{Fore.CYAN}Generating {count} wallets...")
    tasks = [process_wallet(i + 1) for i in range(count)]
    for _ in tqdm(asyncio.as_completed(tasks), total=len(tasks), desc="Progress", ncols=80, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}"):
        await _
    
    print(f"{Style.BRIGHT + Fore.GREEN}COMPLETED: {successful_wallets} WALLETS GENERATED SUCCESSFULLY")

def get_wallet_count() -> int:
    try:
        print(f"{Fore.CYAN}Enter the number of wallets to create (default 1): ", end='')
        count = input().strip()
        return int(count) if count else 1
    except ValueError:
        print(f"{Fore.RED}Invalid input, using default value: 1")
        return 1

# Transaction sending functions
def load_wallet():
    try:
        with open('wallet.json', 'r') as f:
            d = json.load(f)
        priv = d.get('priv')
        addr = d.get('addr')
        rpc = d.get('rpc', DEFAULT_RPC)
        if not rpc.startswith(('http://', 'https://')):
            print(f"{Fore.RED}[ERROR] Invalid RPC URL in wallet.json: {rpc}")
            return None, None, None, None, None
        sk = SigningKey(base64.b64decode(priv))
        pub = base64.b64encode(sk.verify_key.encode()).decode()
        return priv, addr, rpc, sk, pub
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] wallet.json not found. Please create it.")
        return None, None, None, None, None
    except Exception as e:
        print(f"{Fore.RED}[ERROR] Failed to load wallet: {e}")
        return None, None, None, None, None

async def make_request(session, method, rpc, path, data=None, timeout=REQUEST_TIMEOUT):
    url = f"{rpc}{path}"
    for attempt in range(MAX_RETRIES):
        try:
            async with session.request(method, url, json=data, timeout=aiohttp.ClientTimeout(total=timeout)) as resp:
                text = await resp.text()
                try:
                    json_data = json.loads(text)
                except json.JSONDecodeError:
                    json_data = None
                return resp.status, text, json_data
        except asyncio.TimeoutError:
            if attempt < MAX_RETRIES - 1:
                print(f"{Fore.YELLOW}Request timed out, retrying ({attempt + 1}/{MAX_RETRIES})...")
                await asyncio.sleep(RETRY_DELAY)
                continue
            return 0, "timeout", None
        except aiohttp.ClientConnectorError as e:
            if attempt < MAX_RETRIES - 1:
                print(f"{Fore.YELLOW}Connection error: {e}, retrying ({attempt + 1}/{MAX_RETRIES})...")
                await asyncio.sleep(RETRY_DELAY)
                continue
            return 0, f"connection error: {e}", None
        except Exception as e:
            return 0, str(e), None
    return 0, "max retries exceeded", None

async def get_account_state(session, rpc, addr):
    status, text, json_data = await make_request(session, 'GET', rpc, f'/balance/{addr}')
    if status == 200 and json_data:
        return int(json_data.get('nonce', 0)), float(json_data.get('balance', 0))
    elif status == 404:
        return 0, 0.0
    print(f"{Fore.RED}Could not fetch balance/nonce. Status: {status}, Response: {text}")
    return None, None

def create_transaction(addr, pub_key, sk, to, amount, nonce):
    tx = {
        "from": addr,
        "to_": to,
        "amount": str(int(amount * 1_000_000)),
        "nonce": int(nonce),
        "ou": "1",
        "timestamp": time.time()
    }
    tx_bytes = json.dumps(tx, separators=(",", ":")).encode('utf-8')
    signature = base64.b64encode(sk.sign(tx_bytes).signature).decode()
    tx.update(signature=signature, public_key=pub_key)
    tx_hash = hashlib.sha256(tx_bytes).hexdigest()
    return tx, tx_hash

async def send_transaction(session, rpc, tx):
    status, text, json_data = await make_request(session, 'POST', rpc, '/send-tx', data=tx)
    if status == 200 and ((json_data and json_data.get('status') == 'accepted') or 'ok' in text.lower()):
        tx_hash = json_data.get('tx_hash') if json_data else text.split()[-1]
        return True, tx_hash
    return False, json_data.get('error', text) if json_data else text

async def send_transactions():
    priv, addr, rpc, sk, pub = load_wallet()
    if not addr:
        return

    print(f"{Fore.GREEN}Wallet loaded for address: {addr}")

    try:
        with open(ADDRESS_FILE, 'r') as f:
            recipients = [line.strip() for line in f if line.strip() and re.match(r"^oct[1-9A-HJ-NP-Za-km-z]{41,44}$", line.strip())]
        if not recipients:
            print(f"{Fore.RED}No valid addresses found in {ADDRESS_FILE}.")
            return
        print(f"{Fore.CYAN}Found {len(recipients)} valid addresses in {ADDRESS_FILE}.")
    except FileNotFoundError:
        print(f"{Fore.RED}[ERROR] The file '{ADDRESS_FILE}' was not found.")
        return

    async with aiohttp.ClientSession() as session:
        current_nonce, balance = await get_account_state(session, rpc, addr)
        if current_nonce is None:
            return

        total_cost = len(recipients) * AMOUNT_TO_SEND
        print(f"{Fore.YELLOW}Current Balance: {balance:.6f} OCT")
        print(f"{Fore.YELLOW}Total to send: {total_cost:.6f} OCT to {len(recipients)} addresses.")

        if balance < total_cost:
            print(f"{Fore.RED}Insufficient balance to complete all transactions.")
            return

        confirm = input(f"{Fore.CYAN}Proceed with sending? (y/n): ").lower()
        if confirm != 'y':
            print(f"{Fore.YELLOW}Aborted by user.")
            return

        s_total, f_total = 0, 0
        next_nonce = current_nonce + 1

        for i, to_address in enumerate(tqdm(recipients, desc="Sending Transactions", ncols=80, bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt}")):
            print(f"{Fore.CYAN}[{i+1}/{len(recipients)}] Sending {AMOUNT_TO_SEND} OCT to {to_address[:15]}...")
            transaction, tx_hash = create_transaction(addr, pub, sk, to_address, AMOUNT_TO_SEND, next_nonce)
            ok, result_msg = await send_transaction(session, rpc, transaction)

            if ok:
                print(f"{Fore.GREEN}  Success! Hash: {TX_EXPLORER_URL}{result_msg}")
                s_total += 1
                next_nonce += 1
            else:
                print(f"{Fore.RED}  Failed! Reason: {result_msg}")
                f_total += 1

            await asyncio.sleep(0.5)

        print(f"\n{Style.BRIGHT + Fore.GREEN}--- Sending Complete ---")
        print(f"{Fore.GREEN}Successful transactions: {s_total}")
        print(f"{Fore.RED}Failed transactions: {f_total}")
        print(f"{Fore.GREEN}------------------------")

# Animation for loading effect
def loading_animation():
    animation = "|/-\\"
    for i in range(10):
        sys.stdout.write(f"\r{Fore.YELLOW}Initializing{animation[i % len(animation)]}")
        sys.stdout.flush()
        time.sleep(0.1)
    sys.stdout.write("\r" + " " * 20 + "\r")
    sys.stdout.flush()

# Advanced CLI menu
def display_menu():
    banner = text2art("OCTRA", font="block")
    print(f"{Style.BRIGHT + Fore.CYAN}{banner}")
    print(f"{Style.BRIGHT + Fore.MAGENTA}==========================================")
    print(f"{Fore.CYAN}           OCTRA Auto Tx Bot By Kazuha           ")
    print(f"{Fore.CYAN}             LETS FUCK THIS TESTNET          ")
    print(f"{Fore.MAGENTA}==========================================")
    print(f"{Fore.GREEN}1. Generate Wallets")
    print(f"{Fore.YELLOW}2. Send Transactions")
    print(f"{Fore.RED}3. Exit")
    print(f"{Fore.MAGENTA}==========================================")

async def main():
    loading_animation()
    while True:
        display_menu()
        choice = input(f"{Fore.CYAN}Enter your choice (1-3): ").strip()

        if choice == '1':
            print(f"{Style.BRIGHT + Fore.GREEN}NEW WALLET GENERATION - OCTRA WALLET")
            count = get_wallet_count()
            await generate_multiple_wallets(count)
        elif choice == '2':
            await send_transactions()
        elif choice == '3':
            print(f"{Fore.RED}Exiting...")
            break
        else:
            print(f"{Fore.RED}Invalid choice. Please enter 1, 2, or 3.")

if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        print(f"\n{Fore.RED}Operation cancelled by user.")
