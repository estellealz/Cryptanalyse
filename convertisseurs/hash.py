# convertisseurs/hash.py

import sys
import os
import struct

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from crackwordlist import crack_wordlist


# ============================================================
# MD4
# ============================================================

def _lrot(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def md4(data: bytes) -> bytes:
    msg = bytearray(data)
    orig_len = (8 * len(msg)) & 0xffffffffffffffff
    msg.append(0x80)

    while len(msg) % 64 != 56:
        msg.append(0)

    msg += struct.pack("<Q", orig_len)

    h = [0x67452301, 0xefcdab89, 0x98badcfe, 0x10325476]

    F = lambda x, y, z: (x & y) | (~x & z)
    G = lambda x, y, z: (x & y) | (x & z) | (y & z)
    H = lambda x, y, z: x ^ y ^ z

    order3 = [0, 8, 4, 12, 2, 10, 6, 14,
              1, 9, 5, 13, 3, 11, 7, 15]

    for off in range(0, len(msg), 64):
        X = list(struct.unpack("<16I", msg[off:off+64]))
        a, b, c, d = h

        for i in range(16):
            a = _lrot((a + F(b, c, d) + X[i]) & 0xffffffff, [3,7,11,19][i%4])
            a, b, c, d = d, a, b, c

        for i in range(16):
            k = (i % 4) * 4 + (i // 4)
            a = _lrot((a + G(b, c, d) + X[k] + 0x5A827999) & 0xffffffff, [3,5,9,13][i%4])
            a, b, c, d = d, a, b, c

        for i in range(16):
            k = order3[i]
            a = _lrot((a + H(b, c, d) + X[k] + 0x6ED9EBA1) & 0xffffffff, [3,9,11,15][i%4])
            a, b, c, d = d, a, b, c

        h = [(x+y) & 0xffffffff for x,y in zip(h,(a,b,c,d))]

    return struct.pack("<4I", *h)


# ============================================================
# NTLM
# ============================================================

def ntlm_hash(password: str) -> str:
    return md4(password.encode("utf-16le")).hex()


# ============================================================
# DCC1 CORRECT
# ============================================================

def dcc1_hash(password: str, username: str) -> str:
    pwd_md4 = md4(password.encode("utf-16le"))
    combo = pwd_md4 + username.lower().encode("utf-16le")
    return md4(combo).hex()


# ============================================================
# PARSEUR AUTOMATIQUE IMPACKET
# ============================================================

def extract_correct_hash(file_content):
    """
    Extrait automatiquement le hash DCC1 ou NTLM utile.
    Gère automatiquement secretsdump / Impacket.
    """

    lines = file_content.splitlines()

    candidates = []

    for line in lines:

        # cas DCC1 root-me :
        # rootme.local/administrator:HASH:administrator
        if "administrator" in line.lower() and line.count(":") >= 2:
            parts = line.split(":")
            user = parts[0].split("/")[-1]
            hash_ = parts[1]
            if len(hash_) == 32:
                return user, hash_

    # fallback
    for line in lines:
        if ":" in line:
            u, h = line.split(":", 1)
            h = h.strip()
            if len(h) == 32:
                return u.strip(), h.lower()

    return None, None


# ============================================================
# MENU
# ============================================================

def hash_cracker_menu():
    print("\n=== Crackeur NTLM / DCC1 (mscash) ===")
    print("Glissez le fichier dump (secretsdump) :\n")

    path = input("> ").strip().replace('"', '')
    if not os.path.isfile(path):
        print("❌ Fichier introuvable.")
        return

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    username, hash_ = extract_correct_hash(content)

    if not username:
        print("❌ Impossible d'extraire le hash.")
        return

    print(f"\n➡ Username détecté : {username}")
    print(f"➡ Hash détecté     : {hash_}")

    print("\n1 = NTLM")
    print("2 = DCC1 / mscash (Root-Me)")
    print("0 = Quitter")

    c = input("> ").strip()

    print("\nGlissez votre wordlist :")
    wl = input("> ").strip().replace('"','')

    if c == "1":
        crack_wordlist(ntlm_hash, hash_, wl, username=None, hash_type="NTLM")

    elif c == "2":
        crack_wordlist(None, hash_, wl, username=username, hash_type="DCC1")

    else:
        return


if __name__ == "__main__":
    hash_cracker_menu()
