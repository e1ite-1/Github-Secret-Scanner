import os
import re
import sys
import json
import tempfile
import subprocess
import shutil


patterns = {
    "AWS": r"\bAKIA[0-9A-Z]{16}\b",

    "GitHub Token":
        r"\b(?:ghp|gho|ghu|ghr)_[A-Za-z0-9]{20,255}\b",

    "GitHub Fine-Grained":
        r"\bgithub_pat_[A-Za-z0-9_]{20,255}\b",

    "GitHub App Token":
        r"\bghs_[A-Za-z0-9_.-]{20,}\b",

    "Google":
        r"\bAIza[0-9A-Za-z_-]{35}\b",

    "Stripe Secret":
        r"\b(?:sk|rk)_(?:live|test)_[A-Za-z0-9]{16,}\b",

    "Slack Token":
        r"\b(?:xoxb|xoxp|xapp)-[A-Za-z0-9-]{20,}\b",

    "Twilio API Key":
        r"\bSK[0-9a-fA-F]{32}\b",

    "Hugging Face":
        r"\bhf_[A-Za-z0-9]{20,}\b",

    "Generic":
        r'(?i)(?:api[_-]?key|secret|token)'
        r'\s*[:=]\s*["\']?'
        r'([A-Za-z0-9_.-]{20,})',

    "Azure Client Secret":
        r'(?i)(?:ClientSecret|AppSecret)\s*[:=]\s*["\']?([A-Za-z0-9._~-]{20,40})',

    "OpenAI API Key":
        r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}\b",

# -------------------------
    # PRIVATE KEYS
    # -------------------------

    "OpenSSH Private Key":
        r"-----BEGIN OPENSSH PRIVATE KEY-----",

    "RSA Private Key":
        r"-----BEGIN RSA PRIVATE KEY-----",

    "EC Private Key":
        r"-----BEGIN EC PRIVATE KEY-----",

    "Generic Private Key":
        r"-----BEGIN PRIVATE KEY-----",

    "PGP Private Key":
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----",

    "PuTTY Private Key":
        r"^PuTTY-User-Key-File-\d+:",


    # -------------------------
    # DATABASE CREDENTIALS
    # -------------------------

    "PostgreSQL Credentials":
        r'(?i)\bpostgres(?:ql)?://[^:\s/@]+:[^@\s/]+@[^\s"\']+',

    "MySQL Credentials":
        r'(?i)\bmysql://[^:\s/@]+:[^@\s/]+@[^\s"\']+',

    "MongoDB Credentials":
        r'(?i)\bmongodb(?:\+srv)?://[^:\s/@]+:[^@\s/]+@[^\s"\']+',


    # -------------------------
    # PASSWORDS
    # -------------------------

    "Hardcoded Password":
        r'''(?i)\b(?:password|passwd|pwd|db_password|database_password)
        \b\s*[:=]\s*["']([^"' \t\r\n]{8,})["']''',


    # -------------------------
    # AUTH TOKENS / HEADERS
    # -------------------------

    "Bearer Token":
        r'(?i)\bAuthorization\s*:\s*Bearer\s+([A-Za-z0-9._~+/\-]{20,}=*)',

    "Basic Auth":
        r'(?i)\bAuthorization\s*:\s*Basic\s+([A-Za-z0-9+/]{12,}={0,2})',


    # -------------------------
    # JWT TOKENS
    # -------------------------

    "JWT Token":
        r'\beyJ[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b',

    }

SUSPICIOUS_EXTENSIONS = {
    ".json", ".yaml", ".yml",
    ".toml", ".ini", ".cfg", ".conf",
    ".properties", ".log",
    ".bak", ".backup", ".tmp",
    ".key", ".secret", ".private",
    ".sql"
}


def suspicious_file(name):
    name = name.lower()

    # Special environment files
    if name == ".env" or name == ".envrc":
        return True

    # Also catch .env.local, .env.production, etc.
    if name.startswith(".env."):
        return True

    # Normal extensions
    return any(
        name.endswith(ext)
        for ext in SUSPICIOUS_EXTENSIONS
    )

#AWS, GitHub, Stripe, and OpenAI

def mask(secret):
    return secret[:4] + "*" * max(0, len(secret) - 8) + secret[-4:]


def scan(target):
    findings = []

    # Single file
    if os.path.isfile(target):
        files_to_scan = [target]
        base_folder = os.path.dirname(target)

    # Folder
    elif os.path.isdir(target):
        files_to_scan = []
        base_folder = target

        for root, dirs, files in os.walk(target):
            dirs[:] = [d for d in dirs if d != ".git"]

            for name in files:
                path = os.path.join(root, name)

                files_to_scan.append(path)


    else:
        print("ERROR: Path does not exist:", target)
        return []

    print("Files found:", len(files_to_scan))

    for path in files_to_scan:
        print("Scanning:", path)

        try:
            with open(path, "r", encoding="utf-8", errors="ignore") as f:

                for line_num, line in enumerate(f, 1):

                    for key_type, regex in patterns.items():

                        for match in re.finditer(regex, line):

                            secret = (
                                match.group(1)
                                if match.lastindex
                                else match.group()
                            )

                            findings.append({
                                "type": key_type,
                                "file": os.path.basename(path),
                                "line": line_num,
                                "secret": mask(secret)
                            })

        except Exception as e:
            print("Could not read:", path)
            print("Reason:", e)

    return findings


if len(sys.argv) < 2:
    print("Usage: py scanner.py <folder or GitHub URL>")
    sys.exit()


target = sys.argv[1]
temp = None

try:

    if target.startswith("https://github.com/"):

        temp = tempfile.mkdtemp()

        subprocess.run(
            ["git", "clone", "--depth", "1", target, temp],
            check=True
        )

        folder = temp

    else:
        folder = target


    results = scan(folder)

    print(f"\nFound {len(results)} possible secret(s)\n")

    for result in results:

        print(
            f"{result['type']} | "
            f"{result['file']}:{result['line']} | "
            f"{result['secret']}"
        )


    with open("report.json", "w") as f:
        json.dump(results, f, indent=4)

    print("\nReport saved as report.json")


finally:

    if temp:
        shutil.rmtree(temp)