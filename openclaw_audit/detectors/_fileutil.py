"""Utilidad compartida de los detectores: iterar .sol del SOURCE de forma resiliente."""
import os
from pathlib import Path

# Dirs a SALTAR: deps + BUILD (out/artifacts/cache/broadcast). Los detectores escanean SOURCE,
# no artefactos generados. Además el fuzzer lanza `forge clean` que BORRA out/ en paralelo →
# el rglob('*.sol') petaba (FileNotFoundError: <repo>/out) y el detector saltaba el repo ENTERO,
# perdiendo todos sus bugs. Bug hallado en vivo 14-jun.
_SKIP_DIRS = {"node_modules", ".git", "lib", "out", "artifacts", "cache",
              "broadcast", "forge-cache", ".cache", "typechain", "typechain-types",
              "dependencies", "packages", "vendor", "remappings"}

# Marcadores de TEST/MOCK/script (out-of-scope en bounties). Un bug en un .t.sol o /mock/ NO es
# vulnerabilidad real → enviarlo = rechazo + daño de reputación (lo que throttleó la cuenta).
# Mismos marcadores que analyzer._is_test_path. Bug 14-jun: PatternEngine marcaba math.t.sol.
_TEST_MARKERS = ("/test/", "/tests/", "/testing/", "/test-utils/", "/mock", "/mocks/",
                 "/fixture", "/fixtures/", ".t.sol", ".test.sol", "/script/", "/scripts/",
                 "test-contracts", "/examples/", "/example/", "/sample")


def is_test_file(path) -> bool:
    """True si la ruta es código de TEST/MOCK/script (no desplegable → findings = falsos positivos)."""
    p = str(path).lower()
    return any(m in p for m in _TEST_MARKERS)


def iter_sol_files(repo_path, skip_tests: bool = True) -> list:
    """Itera los .sol del SOURCE de forma RESILIENTE (os.walk, salta dirs de build, ficheros de
    test/mock, y tolera borrados concurrentes del fuzzer). Reemplaza el rglob('*.sol') frágil."""
    found = []
    try:
        for root, dirs, files in os.walk(str(repo_path), onerror=lambda e: None, followlinks=False):
            dirs[:] = [d for d in dirs if d not in _SKIP_DIRS]
            for fn in files:
                if not fn.endswith(".sol"):
                    continue
                fp = Path(root) / fn
                if skip_tests and is_test_file(fp):
                    continue
                found.append(fp)
    except Exception:
        pass
    return found


def strip_comments(src: str) -> str:
    """Reemplaza comentarios // y /* */ por espacios PRESERVANDO longitud y saltos de línea (los números de
    línea y offsets se mantienen). Evita FP de detectores que matchean código de EJEMPLO dentro de comentarios."""
    out = []
    i, n = 0, len(src)
    while i < n:
        two = src[i:i + 2]
        if two == "//":
            j = src.find("\n", i)
            if j == -1:
                j = n
            out.append(" " * (j - i))
            i = j
        elif two == "/*":
            j = src.find("*/", i + 2)
            j = n if j == -1 else j + 2
            out.append("".join("\n" if c == "\n" else " " for c in src[i:j]))
            i = j
        else:
            out.append(src[i])
            i += 1
    return "".join(out)
