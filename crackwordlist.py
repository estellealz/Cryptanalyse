# crackwordlist.py

import os
import sys
import time
import multiprocessing as mp


# ============================================================
# Format HH:MM:SS
# ============================================================
def format_seconds(sec):
    sec = int(sec)
    return f"{sec//3600:02d}:{(sec%3600)//60:02d}:{sec%60:02d}"


# ============================================================
# WORKER — GLOBAL (Windows obligatoire)
# ============================================================
def worker(hash_type, username, target_hash, queue_in, queue_out):
    """
    Traite un bloc de mots de passe.
    hash_type : 'NTLM' ou 'DCC1'
    """

    from convertisseurs.hash import ntlm_hash, dcc1_hash  # import interne = OK Windows

    while True:
        block = queue_in.get()

        if block == "STOP":
            queue_out.put(("DONE", None))
            return

        for pwd in block:
            pwd = pwd.strip()

            # === NTLM ===
            if hash_type == "NTLM":
                if ntlm_hash(pwd) == target_hash:
                    queue_out.put(("FOUND", pwd))
                    return

            # === DCC1 ===
            elif hash_type == "DCC1":
                if dcc1_hash(pwd, username) == target_hash:
                    queue_out.put(("FOUND", pwd))
                    return

            else:
                raise ValueError(f"Type de hash inconnu : {hash_type}")

        queue_out.put(("BLOCK_DONE", len(block)))


# ============================================================
# FEEDER — GLOBAL
# ============================================================
def feed_blocks(wordlist_path, block_size, queue_in, cpu_count):
    """Envoie dynamiquement les blocs de la wordlist aux workers."""
    with open(wordlist_path, "r", encoding="utf-8", errors="ignore") as f:
        block = []
        for line in f:
            block.append(line)
            if len(block) >= block_size:
                queue_in.put(block)
                block = []

        if block:
            queue_in.put(block)

    # Fin
    for _ in range(cpu_count):
        queue_in.put("STOP")


# ============================================================
# FONCTION PRINCIPALE APPELÉE PAR hash.py
# ============================================================
def crack_wordlist(hash_func, target_hash, wordlist_path, username=None, hash_type="DCC1"):
    """
    Crack en multiprocessing dynamique (rapide + stable Windows)
    """

    if not os.path.isfile(wordlist_path):
        print("❌ Wordlist introuvable.")
        return None

    print(f"\n>>> Wordlist : {os.path.basename(wordlist_path)}")

    try:
        total = sum(1 for _ in open(wordlist_path, "r", errors="ignore"))
    except:
        print("❌ Erreur de lecture.")
        return None

    print(f">>> {total:,} lignes chargées\n")

    cpu_count = max(2, mp.cpu_count() - 1)
    print(f">>> CPU utilisés : {cpu_count}")

    block_size = 10000

    queue_in = mp.Queue(maxsize=cpu_count * 2)
    queue_out = mp.Queue()

    # --- launch workers ---
    processes = []
    for _ in range(cpu_count):
        p = mp.Process(target=worker,
                       args=(hash_type, username, target_hash, queue_in, queue_out))
        p.start()
        processes.append(p)

    # --- launch feeder ---
    feeder = mp.Process(target=feed_blocks,
                        args=(wordlist_path, block_size, queue_in, cpu_count))
    feeder.start()

    processed = 0
    finished = 0
    start = time.time()
    bar_width = 30

    while finished < cpu_count:
        msg, value = queue_out.get()

        # Mot trouvé
        if msg == "FOUND":
            for p in processes:
                p.terminate()
            feeder.terminate()

            print("\n🔥 Mot trouvé :", value)
            print("⏱ Temps :", format_seconds(time.time() - start))
            return value

        # Bloc traité
        elif msg == "BLOCK_DONE":
            processed += value
            if processed > total:
                processed = total

            progress = processed / total
            filled = int(progress * bar_width)

            bar = (
                "\033[92m" + "█" * filled +
                "\033[90m" + "░" * (bar_width - filled) +
                "\033[0m"
            )

            percent = int(progress * 100)

            elapsed = time.time() - start
            speed = processed / elapsed if elapsed > 0 else 0
            eta = format_seconds((total - processed) / speed) if speed > 0 else "--:--:--"

            sys.stdout.write(
                f"\r[{bar}] {percent:3d}%  "
                f"({processed:,}/{total:,})  Speed: {speed:,.0f}/sec  ETA: {eta}"
            )
            sys.stdout.flush()

        # Fin d'un worker
        elif msg == "DONE":
            finished += 1

    print("\n❌ Aucun mot trouvé.")
    print("⏱ Temps :", format_seconds(time.time() - start))
    return None
