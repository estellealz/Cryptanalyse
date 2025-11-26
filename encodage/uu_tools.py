# convertisseurs/uu_tools.py

"""
Convertisseur UUencode / Uudecode autonome.
Fonctionne avec :
    python convertisseurs/uu_tools.py

Ajouts :
- Décodage compatible Root-Me UUEVIEW
- Choix du fichier sur le PC pour le décodage
"""

import uu
import io
import os


def uu_encode(text: str) -> str:
    """Encode une chaîne en UUencode."""
    input_bytes = text.encode("utf-8")
    input_buffer = io.BytesIO(input_bytes)
    output_buffer = io.BytesIO()

    uu.encode(input_buffer, output_buffer, "fichier.txt")

    return output_buffer.getvalue().decode("utf-8")


def clean_uudecode_data(encoded_data: str) -> str:
    """
    Extrait automatiquement la vraie section UUencode d’un fichier Root-Me :
    - ignore '_=_'
    - ignore 'Part 001'
    - garde seulement la section entre 'begin' et 'end'
    """
    lines = encoded_data.splitlines()

    begin_index = None
    for i, line in enumerate(lines):
        if line.lower().startswith("begin "):
            begin_index = i
            break

    if begin_index is None:
        raise ValueError("Aucune ligne 'begin' trouvée dans le fichier.")

    end_index = None
    for i in range(begin_index, len(lines)):
        if lines[i].strip() == "end":
            end_index = i
            break

    if end_index is None:
        raise ValueError("Aucune ligne 'end' trouvée dans le fichier.")

    return "\n".join(lines[begin_index:end_index + 1])


def uu_decode_from_file(path: str) -> str:
    """
    Lit un fichier UUencode, nettoie le format UUEVIEW et décode.
    """
    if not os.path.isfile(path):
        raise FileNotFoundError("Fichier introuvable.")

    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        content = f.read()

    # Nettoyer et garder uniquement le vrai bloc begin/end
    uu_block = clean_uudecode_data(content)

    # Décodage
    input_buffer = io.BytesIO(uu_block.encode("utf-8"))
    output_buffer = io.BytesIO()

    uu.decode(input_buffer, output_buffer)

    return output_buffer.getvalue().decode("utf-8", errors="replace")


def uu_menu():
    """Menu interactif UUencode / Uudecode."""
    print("\n=== Convertisseur UUencode / Uudecode ===")
    print("1 = UUencode (Texte -> UU)")
    print("2 = Uudecode (à partir d'un fichier)")
    print("0 = Quitter")
    print("----------------------------------------")

    mode = input("Choix : ").strip()

    if mode == "1":
        texte = input("Texte à encoder : ")
        print("\n--- Bloc UUencode ---")
        print(uu_encode(texte))

    elif mode == "2":
        print("Chemin du fichier UUencode : (drag & drop ou chemin complet)")
        path = input("> ").strip().replace('"', '')

        try:
            result = uu_decode_from_file(path)
            print("\n--- Résultat décodé ---")
            print(result)
        except Exception as e:
            print("\nErreur :", e)

    elif mode == "0":
        return

    else:
        print("Choix inconnu.")


if __name__ == "__main__":
    uu_menu()
