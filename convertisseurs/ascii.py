# convertisseurs/ascii.py

"""
Convertisseur ASCII (décimal, hex, binaire, texte -> décimal)
Ajout du mode : décoder depuis un fichier (drag & drop du chemin)
"""

from typing import List
import os


# ---------------------------------------
# UTILITAIRES
# ---------------------------------------

def _split_tokens(data: str) -> List[str]:
    """Découpe proprement les valeurs ASCII."""
    for sep in [",", ";", "\n", "\t"]:
        data = data.replace(sep, " ")
    return [t for t in data.split(" ") if t.strip()]


# ---------------------------------------
# DÉCODEURS
# ---------------------------------------

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


def ascii_from_hex(data: str) -> str:
    """Gère '48 65 6c' et '48656c6c6f'"""
    clean = data.replace(" ", "").lower().replace("0x", "")
    if len(clean) % 2 != 0:
        return "Erreur : hex impair."

    tokens = [clean[i:i + 2] for i in range(0, len(clean), 2)]
    chars = []
    for t in tokens:
        try:
            chars.append(chr(int(t, 16)))
        except:
            chars.append("�")
    return "".join(chars)


def ascii_from_binary(data: str) -> str:
    tokens = _split_tokens(data)
    chars = []
    for t in tokens:
        try:
            chars.append(chr(int(t, 2)))
        except Exception:
            chars.append("�")
    return "".join(chars)


def ascii_to_decimal(text: str) -> str:
    return " ".join(str(ord(c)) for c in text)


# ---------------------------------------
# MODE FICHIER
# ---------------------------------------

def ascii_decode_from_file(path: str, mode: str) -> str:
    """Lit un fichier et décode selon le mode choisi."""
    if not os.path.isfile(path):
        raise FileNotFoundError("Fichier introuvable.")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    if mode == "1":
        return ascii_from_decimal(content)
    elif mode == "2":
        return ascii_from_hex(content)
    elif mode == "3":
        return ascii_from_binary(content)
    else:
        raise ValueError("Mode de fichier inconnu.")


# ---------------------------------------
# MENU INTERACTIF
# ---------------------------------------

def ascii_menu():
    print("\n=== Convertisseur ASCII ===")
    print("1 = Décimal      -> Texte")
    print("2 = Hexadécimal  -> Texte")
    print("3 = Binaire      -> Texte")
    print("4 = Texte        -> Décimal")
    print("5 = Charger un fichier (drag & drop)")
    print("0 = Quitter")
    print("--------------------------------")

    mode = input("Choix : ").strip()

    if mode == "1":
        chaine = input("Chaîne décimale : ")
        print("Résultat :", ascii_from_decimal(chaine))

    elif mode == "2":
        chaine = input("Chaîne hex : ")
        print("Résultat :", ascii_from_hex(chaine))

    elif mode == "3":
        chaine = input("Chaîne binaire : ")
        print("Résultat :", ascii_from_binary(chaine))

    elif mode == "4":
        texte = input("Texte à convertir : ")
        print("Décimal :", ascii_to_decimal(texte))

    elif mode == "5":
        print("Veuillez glisser le fichier ici (drag & drop) :")
        path = input("> ").strip().replace('"', '')

        print("\nFichier importé :", path)
        print("Choisissez le mode de décodage :")
        print("1 = Décimal")
        print("2 = Hex")
        print("3 = Binaire")
        submode = input("Mode fichier : ")

        try:
            result = ascii_decode_from_file(path, submode)
            print("\n--- Résultat du fichier ---")
            print(result)
        except Exception as e:
            print("Erreur :", e)

    elif mode == "0":
        return

    else:
        print("Mode inconnu.")


if __name__ == "__main__":
    ascii_menu()
