# convertisseurs/hash.py

import sys
import os
import struct
import re

# Ajout du dossier parent pour importer crackwordlist
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from crackwordlist import crack_wordlist


# ============================================================
# MD4 (NTLM + DCC1)
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

        # Round 1
        for i in range(16):
            a = _lrot((a + F(b, c, d) + X[i]) & 0xffffffff, [3, 7, 11, 19][i % 4])
            a, b, c, d = d, a, b, c

        # Round 2
        for i in range(16):
            k = (i % 4) * 4 + (i // 4)
            a = _lrot((a + G(b, c, d) + X[k] + 0x5A827999) & 0xffffffff, [3, 5, 9, 13][i % 4])
            a, b, c, d = d, a, b, c

        # Round 3
        for i in range(16):
            k = order3[i]
            a = _lrot((a + H(b, c, d) + X[k] + 0x6ED9EBA1) & 0xffffffff, [3, 9, 11, 15][i % 4])
            a, b, c, d = d, a, b, c

        h = [(x + y) & 0xffffffff for x, y in zip(h, (a, b, c, d))]

    return struct.pack("<4I", *h)


# ============================================================
# Hashs NTLM + DCC1
# ============================================================

def ntlm_hash(password: str) -> str:
    return md4(password.encode("utf-16le")).hex()


def dcc1_hash(password: str, username: str) -> str:
    pwd_md4 = md4(password.encode("utf-16le"))
    combo = pwd_md4 + username.lower().encode("utf-16le")
    return md4(combo).hex()


# ============================================================
# Détection robuste NTLM / DCC1 / DCC2
# ============================================================

def detect_hash_type(file_content):
    """
    Détection robuste avec priorité :
    1. DCC1 (mscash v1)
    2. DCC2 ($dcc2$...)
    3. NTLM (SAM)
    """

    raw_lines = file_content.splitlines()
    lines = []

    # Nettoyage des lignes (espaces, BOM, tabs)
    for l in raw_lines:
        l = l.strip().replace("\t", "").replace("\r", "")
        l = l.replace("\ufeff", "")
        if l:
            lines.append(l)

    dcc1_candidates = []
    dcc2_candidates = []
    ntlm_candidates = []

    # ---------- DCC1 (format Root-Me : domaine/user:hash:user) ----------
    # Exemple : ROOTME.LOCAL/Administrator:15a57c27...:Administrator
    for l in lines:
        m = re.search(
            r'([A-Za-z0-9._-]+/[A-Za-z0-9._$-]+):([0-9a-fA-F]{32}):([A-Za-z0-9._$-]+)',
            l
        )
        if m:
            domain_user = m.group(1)
            hash_ = m.group(2).lower()
            user2 = m.group(3)
            username = domain_user.split("/")[-1]
            if username.lower() == user2.lower():
                dcc1_candidates.append((username, hash_))

    # ---------- DCC2 ----------
    for l in lines:
        if "$dcc2$" in l.lower():
            # On enlève les espaces internes pour être sûr
            ll = l.replace(" ", "")
            m = re.search(
                r"\$dcc2\$(\d+)#([^#]+)#([0-9a-fA-F]{32})",
                ll,
                re.IGNORECASE
            )
            if m:
                rounds = m.group(1)
                username = m.group(2)
                hash_ = m.group(3).lower()
                dcc2_candidates.append((username, hash_, rounds))

    # ---------- NTLM (SAM: user:rid:lm:ntlm:::) ----------
    for l in lines:
        parts = l.split(":")
        if len(parts) >= 4:
            ntlm = parts[3]
            if len(ntlm) == 32 and all(c in "0123456789abcdefABCDEF" for c in ntlm):
                username = parts[0]
                ntlm_candidates.append((username, ntlm.lower()))

    # PRIORITÉ :
    # 1. DCC1 si dispo (challenge DCC)
    if dcc1_candidates:
        username, hash_ = dcc1_candidates[0]
        return ("DCC1", username, hash_, None)

    # 2. DCC2 si aucun DCC1
    if dcc2_candidates:
        username, hash_, rounds = dcc2_candidates[0]
        return ("DCC2", username, hash_, rounds)

    # 3. NTLM sinon
    if ntlm_candidates:
        username, hash_ = ntlm_candidates[0]
        return ("NTLM", username, hash_, None)

    return (None, None, None, None)


# ============================================================
# Menu principal
# ============================================================

def hash_cracker_menu():
    print("\n=== Crackeur NTLM / DCC1 / DCC2 ===")
    print("Glissez le fichier secretsdump :\n")

    path = input("> ").strip().replace('"', '')
    if not os.path.isfile(path):
        print("❌ Fichier introuvable.")
        return

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    hash_type, username, hash_, rounds = detect_hash_type(content)

    if not hash_type:
        print("❌ Aucun hash détecté.")
        return

    print(f"\n➡ Type détecté : {hash_type}")
    print(f"➡ Username     : {username}")
    print(f"➡ Hash         : {hash_}")
    if rounds:
        print(f"➡ Rounds       : {rounds}")

    # --------------------------------------------------------
    # DCC2 → Hashcat direct, PAS DE WORDLIST
    # --------------------------------------------------------
    if hash_type == "DCC2":
        print("\n🛑 DCC2 détecté → Crack Python impossible.")
        print("→ DCC2 = PBKDF2-HMAC-SHA1 / 10240 itérations.")
        print("→ Hashcat recommandé.")

        out = f"$mscach2${rounds}#{username}#{hash_}"

        with open("hash.txt", "w") as f:
            f.write(out + "\n")

        print("\n✔ Fichier hash.txt généré")
        print("\nCommande Hashcat :")
        print(f"hashcat -m 7100 hash.txt rockyou.txt")
        print("\n🔥 Copie-colle cette commande dans ton terminal.")
        return

    # --------------------------------------------------------
    # NTLM / DCC1 → Crack Python avec wordlist
    # --------------------------------------------------------
    print("\nGlissez votre wordlist :")
    wl = input("> ").strip().replace('"', '')

    if hash_type == "NTLM":
        crack_wordlist(ntlm_hash, hash_, wl, username=None, hash_type="NTLM")
        return

    if hash_type == "DCC1":
        crack_wordlist(
            lambda p: dcc1_hash(p, username),
            hash_, wl,
            username=username,
            hash_type="DCC1"
        )
        return


if __name__ == "__main__":
    hash_cracker_menu()
