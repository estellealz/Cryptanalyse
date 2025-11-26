# convertisseurs/ascii.py

"""
Convertisseur ASCII interactif pour CTF / cryptanalyse.

Modes :
1 = Décimal    -> texte
2 = Hex        -> texte
3 = Binaire    -> texte
4 = Texte      -> ASCII décimal
"""

from typing import List


# ---------------------------------
# Utils
# ---------------------------------

def _split_tokens(data: str) -> List[str]:
    """
    Découpe proprement les valeurs séparées par espaces, virgules, etc.
    """
    for sep in [",", ";", "\n", "\t"]:
        data = data.replace(sep, " ")
    return [t for t in data.split(" ") if t.strip()]


# ---------------------------------
# Décimal -> texte
# ---------------------------------

def ascii_from_decimal(data: str) -> str:
    tokens = _split_tokens(data)
    chars = []
    for t in tokens:
        try:
            code = int(t)
            if 0 <= code <= 255:
                chars.append(chr(code))
            else:
                chars.append("�")
        except ValueError:
            chars.append("�")
    return "".join(chars)


# ---------------------------------
# Hex -> texte (GROS FIX ici)
# ---------------------------------

def ascii_from_hex(data: str) -> str:
    """
    Gère :
    - '48 65 6c'
    - '0x48 0x65'
    - '48656c6c6f' (hex collé)
    """
    data = data.strip()

    # Nettoyage
    for sep in [",", ";", "\n", "\t"]:
        data = data.replace(sep, " ")
    tokens = [t for t in data.split(" ") if t.strip()]

    bytes_tokens = []

    # CAS 1 : une seule chaîne hex collée
    if len(tokens) == 1:
        hex_str = tokens[0].lower()
        if hex_str.startswith("0x"):
            hex_str = hex_str[2:]
        if len(hex_str) % 2 != 0:
            return "Erreur : hex impair."

        # Découpage par octets
        for i in range(0, len(hex_str), 2):
            bytes_tokens.append(hex_str[i:i+2])

    # CAS 2 : plusieurs octets séparés
    else:
        for t in tokens:
            t_clean = t.lower().replace("0x", "")
            bytes_tokens.append(t_clean)

    # Conversion finale
    chars = []
    for b in bytes_tokens:
        try:
            code = int(b, 16)
            chars.append(chr(code) if 0 <= code <= 255 else "�")
        except ValueError:
            chars.append("�")

    return "".join(chars)


# ---------------------------------
# Binaire -> texte
# ---------------------------------

def ascii_from_binary(data: str) -> str:
    tokens = _split_tokens(data)
    chars = []
    for t in tokens:
        try:
            code = int(t, 2)
            if 0 <= code <= 255:
                chars.append(chr(code))
            else:
                chars.append("�")
        except ValueError:
            chars.append("�")
    return "".join(chars)


# ---------------------------------
# Texte -> ASCII (décimal)
# ---------------------------------

def ascii_to_decimal(text: str) -> str:
    return " ".join(str(ord(c)) for c in text)


# ---------------------------------
# MODE INTERACTIF
# ---------------------------------

if __name__ == "__main__":
    print("=== Convertisseur ASCII interactif ===")
    print("1 = Décimal      -> Texte")
    print("2 = Hexadécimal  -> Texte")
    print("3 = Binaire      -> Texte")
    print("4 = Texte        -> Décimal")
    print("------------------------------------")

    mode = input("Mode : ").strip()

    if mode == "1":
        chaine = input("Chaîne décimale (ex: 72 101 108) : ")
        print("Résultat :", ascii_from_decimal(chaine))

    elif mode == "2":
        chaine = input("Chaîne hex (ex: 48 65 6c / 48656c6c6f) : ")
        print("Résultat :", ascii_from_hex(chaine))

    elif mode == "3":
        chaine = input("Chaîne binaire (ex: 01001000 01100101) : ")
        print("Résultat :", ascii_from_binary(chaine))

    elif mode == "4":
        texte = input("Texte : ")
        print("ASCII décimal :", ascii_to_decimal(texte))

    else:
        print("Mode inconnu.")
