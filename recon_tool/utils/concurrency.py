from concurrent.futures import ThreadPoolExecutor, as_completed
from typing import Callable, Iterable, List, Any


def run_parallel(
    func: Callable[[Any], Any],
    items: Iterable[Any],
    max_workers: int = 10,
) -> List[Any]:
    """
    Run a function in parallel over a list of items.
    """
    results = []

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [executor.submit(func, item) for item in items]

        for future in as_completed(futures):
            try:
                results.append(future.result())
            except Exception as exc:
                results.append({"error": str(exc)})

    return results
