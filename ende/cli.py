"""
Command Line Interface for ende.
Provides intuitive auto-detection, single and double encryption (--r),
history tracking, file inspection, and secure file shredding.
Author: asim
"""

import argparse
import sys
from pathlib import Path
from typing import Optional, List

from ende import __version__, __author__, __app_name__
from ende.crypto import AuthenticationError, CryptoError
from ende.format import (
    is_ende_file,
    inspect_header,
    encrypt_file_data,
    decrypt_file_data,
    wrap_existing_ende_with_layer2,
    ContainerError,
    IntegrityError,
)
from ende.history import (
    add_history_entry,
    load_history,
    clear_history,
    format_history_table,
)
from ende.utils import (
    prompt_password,
    format_size,
    calculate_sha256_file,
    calculate_sha256_bytes,
    secure_shred,
)

BANNER = f"""
  ___ _ __   __| | ___ 
 / _ \\ '_ \\ / _` |/ _ \\
|  __/ | | | (_| |  __/  [v{__version__}]
 \\___|_| |_|\\__,_|\\___|
 High-Security File Encryption & Decryption CLI
"""


def parse_arguments(args: Optional[List[str]] = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        prog="ende",
        description="ende - High-Security File Encryption & Decryption CLI",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  ende secret.pdf                  Encrypt 'secret.pdf' -> 'secret.pdf.ende'
  ende secret.pdf.ende             Decrypt 'secret.pdf.ende' back to original file
  ende secret.pdf --r              Double-encrypt 'secret.pdf' (2 layers)
  ende secret.pdf.ende --r         Apply 2nd layer of encryption to existing .ende file
  ende history                     View encryption & decryption audit history
  ende history --clear             Clear history logs
  ende info secret.pdf.ende        Inspect .ende container metadata
  ende secret.pdf --shred          Encrypt and securely wipe original file
        """,
    )

    # Positional target / subcommand
    parser.add_argument(
        "target",
        nargs="?",
        default=None,
        help="Path to file to encrypt/decrypt, or command (history, info).",
    )

    # Second optional positional argument for subcommands (e.g. `ende info file.ende`)
    parser.add_argument(
        "sub_target",
        nargs="?",
        default=None,
        help=argparse.SUPPRESS,
    )

    # Core flags
    parser.add_argument(
        "-r", "--r", "--double",
        dest="double_encrypt",
        action="store_true",
        help="Enable double encryption (2 layers of AES-256-GCM).",
    )
    parser.add_argument(
        "-d", "--decrypt",
        action="store_true",
        help="Explicitly decrypt target file.",
    )
    parser.add_argument(
        "-e", "--encrypt",
        action="store_true",
        help="Explicitly encrypt target file.",
    )
    parser.add_argument(
        "-o", "--output",
        type=str,
        default=None,
        help="Destination path for output file.",
    )
    parser.add_argument(
        "-p", "--password",
        type=str,
        default=None,
        help="Primary password (or layer 1 password).",
    )
    parser.add_argument(
        "--p2",
        type=str,
        default=None,
        help="Secondary password for double encryption (layer 2).",
    )
    parser.add_argument(
        "--no-compress",
        action="store_true",
        help="Disable automatic zlib compression before encryption.",
    )
    parser.add_argument(
        "-s", "--shred",
        action="store_true",
        help="Securely wipe original file after successful operation.",
    )
    parser.add_argument(
        "-f", "--force",
        action="store_true",
        help="Overwrite existing output files without prompting.",
    )

    # History & Info options
    parser.add_argument(
        "-H", "--history",
        action="store_true",
        help="View audit history of encrypted/decrypted files.",
    )
    parser.add_argument(
        "--clear-history",
        action="store_true",
        help="Clear audit history log.",
    )
    parser.add_argument(
        "-I", "--info",
        action="store_true",
        help="Inspect .ende file header and security properties.",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        help="Output history or info in JSON format.",
    )
    parser.add_argument(
        "-v", "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )

    return parser.parse_args(args)


def handle_history(clear: bool = False, as_json: bool = False) -> int:
    """Handles history viewing and clearing."""
    if clear:
        count = clear_history()
        print(f"[+] Cleared {count} records from history.")
        return 0

    records = load_history()
    if as_json:
        import json
        print(json.dumps(records, indent=2))
        return 0

    print(format_history_table(records))
    return 0


def handle_info(file_path: Path) -> int:
    """Inspects header of an .ende file."""
    if not file_path.exists():
        print(f"[!] Error: File '{file_path}' not found.", file=sys.stderr)
        return 1

    try:
        data = file_path.read_bytes()
        info = inspect_header(data)
        file_size = len(data)

        print("\n================ ENDE CONTAINER INFO ================")
        print(f"File Path:        {file_path.resolve()}")
        print(f"Container Size:   {format_size(file_size)} ({file_size} bytes)")
        print(f"Magic Signature:  {info['magic']}")
        print(f"Format Version:   v{info['version']}")
        print(f"Double Encrypted: {'YES (2 layers)' if info['is_double'] else 'No (1 layer)'}")
        print(f"Compression:      {'Enabled' if info['is_compressed'] else 'Disabled'}")
        print(f"KDF Algorithm:    PBKDF2-HMAC-SHA256 (200,000 iterations)")
        print(f"Cipher Algorithm: AES-256-GCM (Authenticated)")
        print("=====================================================\n")
        return 0
    except ContainerError as e:
        print(f"[!] Error: {e}", file=sys.stderr)
        return 1


def confirm_overwrite(destination: Path, force: bool) -> bool:
    """Prompts for overwrite confirmation if target exists."""
    if not destination.exists() or force:
        return True
    try:
        reply = input(f"[?] File '{destination.name}' already exists. Overwrite? [y/N]: ").strip().lower()
        return reply in ("y", "yes")
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Operation cancelled.")
        return False


def run_encryption(
    source_path: Path,
    output_path: Optional[Path],
    password: Optional[str],
    password2: Optional[str],
    double_encrypt: bool,
    compress: bool,
    shred: bool,
    force: bool,
) -> int:
    """Executes encryption of a file."""
    if not source_path.exists():
        print(f"[!] Error: Source file '{source_path}' does not exist.", file=sys.stderr)
        return 1

    if source_path.is_dir():
        print(f"[!] Error: '{source_path}' is a directory. Please provide a file.", file=sys.stderr)
        return 1

    # Check if target is an existing .ende file and double encryption was requested
    is_already_ende = is_ende_file(source_path)
    if is_already_ende and double_encrypt:
        print(f"[*] Detected existing ENDE file '{source_path.name}'.")
        print("[*] Applying 2nd encryption layer (Double Encryption)...")
        dest_path = output_path or source_path

        if not confirm_overwrite(dest_path, force or dest_path == source_path):
            return 1

        try:
            pwd2 = password2 or password
            if not pwd2:
                pwd2 = prompt_password("[?] Enter Layer 2 password: ", confirm=True)

            raw_bytes = source_path.read_bytes()
            new_container = wrap_existing_ende_with_layer2(raw_bytes, pwd2)
            dest_path.write_bytes(new_container)

            sha256 = calculate_sha256_bytes(new_container)
            add_history_entry(
                action="DOUBLE_ENCRYPT",
                source_file=str(source_path),
                target_file=str(dest_path),
                file_size_bytes=len(new_container),
                sha256=sha256,
                layers=2,
                compressed=compress,
                status="SUCCESS",
            )
            print(f"[+] Successfully applied double encryption to: {dest_path}")
            return 0
        except Exception as e:
            print(f"[!] Double encryption failed: {e}", file=sys.stderr)
            return 1

    # Standard encryption (single or double)
    dest_path = output_path or Path(f"{source_path}.ende")
    if not confirm_overwrite(dest_path, force):
        return 1

    # Password collection
    try:
        if double_encrypt:
            print(f"[*] Double Encryption enabled for '{source_path.name}' (2 layers).")
            pwd1 = password or prompt_password("[?] Enter Primary Password (Layer 1): ", confirm=True)
            pwd2 = password2 or prompt_password("[?] Enter Secondary Password (Layer 2 - Double Encryption): ", confirm=True)
        else:
            pwd1 = password or prompt_password(f"[?] Enter password to encrypt '{source_path.name}': ", confirm=True)
            pwd2 = None
    except ValueError as ve:
        print(f"[!] {ve}", file=sys.stderr)
        return 1
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Operation cancelled.")
        return 1

    print(f"[*] Encrypting '{source_path.name}' ({format_size(source_path.stat().st_size)})...")
    try:
        raw_data = source_path.read_bytes()
        orig_sha = calculate_sha256_bytes(raw_data)
        container_bytes = encrypt_file_data(
            data=raw_data,
            original_name=source_path.name,
            password=pwd1,
            compress=compress,
            double_encrypt=double_encrypt,
            password2=pwd2,
        )

        dest_path.write_bytes(container_bytes)
        dest_size = len(container_bytes)

        # Log history
        add_history_entry(
            action="DOUBLE_ENCRYPT" if double_encrypt else "ENCRYPT",
            source_file=str(source_path),
            target_file=str(dest_path),
            file_size_bytes=len(raw_data),
            sha256=orig_sha,
            layers=2 if double_encrypt else 1,
            compressed=compress,
            status="SUCCESS",
        )

        print(f"[+] Successfully encrypted -> '{dest_path.name}' ({format_size(dest_size)})")
        if double_encrypt:
            print("[+] Layers: 2 (Double Encrypted with AES-256-GCM)")
        print(f"[+] Integrity SHA-256: {orig_sha}")

        if shred:
            print(f"[*] Securely shredding original file '{source_path.name}'...")
            secure_shred(source_path)
            print("[+] Original file wiped and removed.")

        return 0
    except Exception as e:
        print(f"[!] Encryption failed: {e}", file=sys.stderr)
        return 1


def run_decryption(
    source_path: Path,
    output_path: Optional[Path],
    password: Optional[str],
    password2: Optional[str],
    shred: bool,
    force: bool,
) -> int:
    """Executes decryption of an .ende file."""
    if not source_path.exists():
        print(f"[!] Error: Source file '{source_path}' does not exist.", file=sys.stderr)
        return 1

    try:
        raw_bytes = source_path.read_bytes()
        header = inspect_header(raw_bytes)
    except ContainerError as ce:
        print(f"[!] Error: '{source_path.name}' is not a valid ENDE file: {ce}", file=sys.stderr)
        return 1

    is_double = header["is_double"]
    if is_double:
        print(f"[*] Detected Double-Encrypted file '{source_path.name}' (2 layers).")

    # Prompt passwords if not provided
    pwd1 = password
    pwd2 = password2

    def pwd_prompt_cb(prompt_msg: str) -> str:
        return prompt_password(f"[?] {prompt_msg}")

    try:
        if is_double:
            if not pwd2 and not pwd1:
                pwd2 = prompt_password("[?] Enter Layer 2 (Outer) password: ")
                pwd1 = prompt_password("[?] Enter Layer 1 (Inner) password: ")
            elif pwd1 and not pwd2:
                # User passed single -p, we can attempt with pwd1, or prompt for layer 1 if needed
                pass
        else:
            if not pwd1:
                pwd1 = prompt_password(f"[?] Enter password to decrypt '{source_path.name}': ")
    except (KeyboardInterrupt, EOFError):
        print("\n[!] Operation cancelled.")
        return 1
    except ValueError as ve:
        print(f"[!] {ve}", file=sys.stderr)
        return 1

    print(f"[*] Decrypting '{source_path.name}'...")
    try:
        metadata, plaintext = decrypt_file_data(
            container_bytes=raw_bytes,
            password=pwd1 or "",
            password2=pwd2,
            pwd_callback=pwd_prompt_cb,
        )

        orig_name = metadata.get("original_name")
        if output_path:
            dest_path = output_path
        elif orig_name:
            # Place in same directory as the .ende file
            dest_path = source_path.parent / orig_name
            # If target would overwrite source_path (e.g. if original was named foo.ende)
            if dest_path.resolve() == source_path.resolve():
                dest_path = source_path.parent / f"decrypted_{orig_name}"
        else:
            # Strip .ende suffix
            clean_name = source_path.stem if source_path.suffix == ".ende" else f"{source_path.name}.decrypted"
            dest_path = source_path.parent / clean_name

        if not confirm_overwrite(dest_path, force):
            return 1

        dest_path.write_bytes(plaintext)
        sha256 = calculate_sha256_bytes(plaintext)

        # Log history
        add_history_entry(
            action="DECRYPT",
            source_file=str(source_path),
            target_file=str(dest_path),
            file_size_bytes=len(plaintext),
            sha256=sha256,
            layers=2 if is_double else metadata.get("layers", 1),
            compressed=metadata.get("compressed", False),
            status="SUCCESS",
        )

        print(f"[+] Successfully decrypted -> '{dest_path}' ({format_size(len(plaintext))})")
        print(f"[+] Restored original file: {dest_path.name}")
        print(f"[+] Integrity verified: SHA-256 {sha256}")

        if shred:
            print(f"[*] Securely shredding encrypted file '{source_path.name}'...")
            secure_shred(source_path)
            print("[+] Encrypted file wiped and removed.")

        return 0
    except AuthenticationError as ae:
        print(f"\n[!] Decryption failed: {ae}", file=sys.stderr)
        return 1
    except IntegrityError as ie:
        print(f"\n[!] Integrity check failed: {ie}", file=sys.stderr)
        return 1
    except Exception as e:
        print(f"\n[!] Error during decryption: {e}", file=sys.stderr)
        return 1


def main(args: Optional[List[str]] = None) -> int:
    """Main CLI entrypoint."""
    parsed = parse_arguments(args)

    # 1. Check history flags/subcommands
    if parsed.history or parsed.clear_history or parsed.target == "history":
        clear = parsed.clear_history or (parsed.target == "history" and parsed.sub_target == "--clear")
        return handle_history(clear=clear, as_json=parsed.json)

    # 2. Check info flag/subcommand
    if parsed.info or parsed.target == "info":
        target_file = parsed.sub_target or (parsed.target if parsed.info else None)
        if not target_file:
            print("[!] Error: Please specify an .ende file to inspect (e.g. `ende info file.ende`).", file=sys.stderr)
            return 1
        return handle_info(Path(target_file))

    # 3. Ensure a target file was provided
    if not parsed.target:
        print(BANNER)
        print("Usage: ende <filename> [options]\n")
        print("Quick Start:")
        print("  ende file.txt                  # Encrypts file.txt -> file.txt.ende")
        print("  ende file.txt.ende             # Decrypts file.txt.ende back to original")
        print("  ende file.txt --r              # Double-encrypts file.txt (2 layers)")
        print("  ende file.txt.ende --r         # Adds 2nd layer to existing .ende file")
        print("  ende history                   # View encryption & decryption log")
        print("\nRun 'ende --help' for all options.")
        return 0

    target_path = Path(parsed.target)
    if not target_path.exists():
        print(f"[!] Error: File '{parsed.target}' not found.", file=sys.stderr)
        return 1

    output_path = Path(parsed.output) if parsed.output else None
    compress = not parsed.no_compress

    # 4. Mode resolution (Explicit or Auto-Detect)
    is_ende = is_ende_file(target_path) or target_path.suffix.lower() == ".ende"

    if parsed.decrypt:
        # Explicit decrypt mode requested
        return run_decryption(
            source_path=target_path,
            output_path=output_path,
            password=parsed.password,
            password2=parsed.p2,
            shred=parsed.shred,
            force=parsed.force,
        )
    elif parsed.encrypt:
        # Explicit encrypt mode requested
        return run_encryption(
            source_path=target_path,
            output_path=output_path,
            password=parsed.password,
            password2=parsed.p2,
            double_encrypt=parsed.double_encrypt,
            compress=compress,
            shred=parsed.shred,
            force=parsed.force,
        )
    else:
        # Auto-detect mode:
        # If target has .ende extension or ENDE magic:
        # - If --r is passed: double-encrypt the file!
        # - Otherwise: decrypt it!
        if is_ende:
            if parsed.double_encrypt:
                # Double encryption on .ende file
                return run_encryption(
                    source_path=target_path,
                    output_path=output_path,
                    password=parsed.password,
                    password2=parsed.p2,
                    double_encrypt=True,
                    compress=compress,
                    shred=parsed.shred,
                    force=parsed.force,
                )
            else:
                # Decrypt mode
                return run_decryption(
                    source_path=target_path,
                    output_path=output_path,
                    password=parsed.password,
                    password2=parsed.p2,
                    shred=parsed.shred,
                    force=parsed.force,
                )
        else:
            # Regular file -> encrypt mode
            return run_encryption(
                source_path=target_path,
                output_path=output_path,
                password=parsed.password,
                password2=parsed.p2,
                double_encrypt=parsed.double_encrypt,
                compress=compress,
                shred=parsed.shred,
                force=parsed.force,
            )


if __name__ == "__main__":
    sys.exit(main())
