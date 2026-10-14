# Ghidra Headless post-script: ETHIO-AI Defender structured program dump.
#
# Executed by app/analyzers/ghidra_analyzer.py through Ghidra's supported
# analyzeHeadless workflow. This script only READS the analyzed program
# database. It never executes, emulates, or detonates the sample.
#
# Environment variables (set by the analyzer):
#   GHIDRA_OUT_FILE      Absolute path where the structured JSON result is written.
#   GHIDRA_MAX_FUNCTIONS Maximum number of functions to dump (default 2000).
#
# Output: a single JSON document describing program identity, architecture,
# entry point, functions, call-graph relationships, imports, exports, and strings.
#
# NOTE: Ghidra runs this file with Jython 2.7 (Python 2 syntax).

import json
import os

try:
    from ghidra.program.util import DefinedDataIterator
except Exception:
    DefinedDataIterator = None


MAX_FUNCTIONS = int(os.environ.get("GHIDRA_MAX_FUNCTIONS", "2000") or "2000")
MAX_STRINGS = 5000
MAX_RELATIONSHIPS = 10000
OUT_FILE = os.environ.get("GHIDRA_OUT_FILE", "")

program = currentProgram  # noqa: F821 - injected by the Ghidra script environment

result = {
    "ok": True,
    "program_name": None,
    "language_id": None,
    "processor": None,
    "compiler": None,
    "image_base": None,
    "entry_point": None,
    "function_count": 0,
    "functions_truncated": False,
    "functions": [],
    "imports": [],
    "exports": [],
    "string_count": 0,
    "strings": [],
    "relationship_count": 0,
    "relationships": [],
    "errors": [],
}


def _safe(section, func):
    """Runs a best-effort extraction step, recording failures without aborting."""
    try:
        return func()
    except Exception as exc:  # noqa: BLE001 - defensive: partial results preferred
        result["errors"].append("%s: %s" % (section, exc))
        return None


# --- 1. Program identity & architecture -------------------------------------
def _identity():
    result["program_name"] = program.getName()
    result["language_id"] = str(program.getLanguageID())
    result["processor"] = str(program.getLanguage().getProcessor())
    try:
        result["compiler"] = str(program.getCompilerSpec().getCompilerSpecID())
    except Exception:
        result["compiler"] = str(program.getCompilerSpec())
    result["image_base"] = str(program.getImageBase())


_safe("identity", _identity)


# --- 2. Entry point ---------------------------------------------------------
def _entry_point():
    ep = program.getEntryPoint()
    if ep is not None:
        result["entry_point"] = str(ep)


_safe("entry_point", _entry_point)


# --- 3. Functions -----------------------------------------------------------
def _functions():
    fm = program.getFunctionManager()
    count = 0
    for func in fm.getFunctions(True):
        if count >= MAX_FUNCTIONS:
            result["functions_truncated"] = True
            break
        body = func.getBody()
        size = 0
        try:
            size = int(body.getNumAddresses())
        except Exception:
            size = 0
        calling_convention = None
        try:
            calling_convention = str(func.getCallingConventionName())
        except Exception:
            calling_convention = None
        result["functions"].append({
            "name": func.getName(),
            "address": str(func.getEntryPoint()),
            "size": size,
            "is_thunk": bool(func.isThunk()),
            "calling_convention": calling_convention,
        })
        count += 1
    result["function_count"] = count


_safe("functions", _functions)


# --- 3b. Function relationships (call-graph edges) --------------------------
def _relationships():
    try:
        task_monitor = monitor  # noqa: F821 - injected by the Ghidra script environment
    except NameError:
        task_monitor = None
    fm = program.getFunctionManager()
    scanned = 0
    edges = 0
    for func in fm.getFunctions(True):
        if scanned >= MAX_FUNCTIONS:
            break
        scanned += 1
        try:
            callees = func.getCalledFunctions(task_monitor)
        except Exception:
            continue
        for callee in callees:
            if edges >= MAX_RELATIONSHIPS:
                break
            try:
                result["relationships"].append({
                    "from_address": str(func.getEntryPoint()),
                    "from_name": func.getName(),
                    "to_address": str(callee.getEntryPoint()),
                    "to_name": callee.getName(),
                })
                edges += 1
            except Exception:
                continue
    result["relationship_count"] = edges


_safe("relationships", _relationships)


# --- 4. Imports (external symbols) ------------------------------------------
def _imports():
    st = program.getSymbolTable()
    seen = {}
    for sym in st.getExternalSymbols():
        try:
            name = sym.getName()
            try:
                namespace = str(sym.getParentNamespace().getName())
            except Exception:
                namespace = "EXTERNAL"
            key = "%s!%s" % (namespace, name)
            if key not in seen:
                seen[key] = True
                result["imports"].append({
                    "name": name,
                    "library": namespace,
                })
        except Exception:
            continue


_safe("imports", _imports)


# --- 5. Exports (external entry points) -------------------------------------
def _exports():
    st = program.getSymbolTable()
    for addr in st.getExternalEntryPointIterator():
        try:
            result["exports"].append(str(addr))
        except Exception:
            continue


_safe("exports", _exports)


# --- 6. Strings -------------------------------------------------------------
def _strings():
    if DefinedDataIterator is None:
        result["errors"].append("strings: DefinedDataIterator unavailable")
        return
    count = 0
    for data in DefinedDataIterator.definedStrings(program):
        if count >= MAX_STRINGS:
            break
        try:
            value = data.getValue()
            if value is None:
                continue
            text = str(value)
            if not text:
                continue
            result["strings"].append({
                "value": text,
                "address": str(data.getAddress()),
            })
            count += 1
        except Exception:
            continue
    result["string_count"] = count


_safe("strings", _strings)


# --- 7. Persist structured JSON ---------------------------------------------
def _write():
    if not OUT_FILE:
        raise ValueError("GHIDRA_OUT_FILE environment variable is not set")
    out_dir = os.path.dirname(OUT_FILE)
    if out_dir and not os.path.isdir(out_dir):
        os.makedirs(out_dir)
    with open(OUT_FILE, "w") as fh:
        json.dump(result, fh)
    print("ETHIO-AI Defender: dumped program info to %s" % OUT_FILE)


try:
    _write()
except Exception as exc:  # noqa: BLE001
    print("ETHIO-AI Defender: failed to write dump: %s" % exc)
    raise
