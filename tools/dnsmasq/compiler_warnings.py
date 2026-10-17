"""Reject compiler/Cargo warnings; preserve known SDK metadata diagnostics."""
import re


ANSI = re.compile(r"\x1b\[[0-?]*[ -/]*[@-~]")
WARNING = re.compile(r"\bwarning(?:\[[^\]]+\])?:", re.I)
SDK_WARNING = re.compile(
    r"^(?:WARNING: Makefile '.+' has a dependency on '.+', which does not exist$|"
    r"(?:[^\s:]+/)?(?:\.config(?:-[^\s:]+)?(?:\.in)?|Config(?:-[^\s:]+)?\.in):\d+:warning:|"
    r"Makefile:\d+: WARNING: skipping [A-Za-z0-9_+.-]+ -- package has no install section$)")


def scan(logs):
    """Only known SDK metadata warnings are exempt; unfamiliar warnings fail."""
    result = {"compiler_or_unclassified": [], "sdk_metadata": []}
    for path in logs:
        for number, raw in enumerate(path.read_text(errors="replace").splitlines(), 1):
            line = ANSI.sub("", raw).strip()
            if WARNING.search(line):
                group = "sdk_metadata" if SDK_WARNING.match(line) else "compiler_or_unclassified"
                result[group].append({"log": path.name, "line": number, "text": line})
    result["strict_compiler_warnings_zero"] = not result["compiler_or_unclassified"]
    return result
