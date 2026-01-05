from pathlib import Path
from typing import List


def load_wordlist(path: str) -> List[str]:
    """
    Load a wordlist file (one entry per line).
    """
    p = Path(path)

    if not p.exists():
        raise FileNotFoundError(f"Wordlist not found: {path}")

    words = []
    with p.open("r", encoding="utf-8", errors="ignore") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                words.append(line)

    return words
