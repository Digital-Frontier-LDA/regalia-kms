"""Find every WRITE to one of this host's own /etc paths in deploy/ and the units (#61, the dm-verity design).

On a verity-/usr host / is a tmpfs and /etc is made from the image at every boot: a file written under /etc is gone
at the next boot. This host's own files live on /var, their /etc names are links made by
units/00-regalia-etc.tmpfiles.conf, and a writer must write the /var name (deploy/baremetal/hostpaths.persistent). The
per-host /etc paths are hostpaths.PER_HOST (held equal to image/etc-inventory.txt by test_baremetal_etc_inventory).

WHAT COUNTS AS A WRITE, by kind of file:
  Python   a call that writes, makes, moves or removes a file (open() with a writing mode, os.open() with a writing
           flag, os.mkdir/rename/replace/link/symlink/unlink/chmod/..., shutil.copy*/move/rmtree, Path.write_*,
           the deploy package's own writers: _install, _write_private, _atomic_json, wg_key, _ensure_trusted_dir,
           and any `.write(path, ...)`), or an argv list whose command writes (cp, mv, install, tee, ...), whose
           path argument RESOLVES to a per-host /etc path: a literal, a module constant (this module's or another
           deploy module's), a parameter's default, a local assignment, +, %, f-strings and os.path.join of those.
           A value only partly known (CONFIG_DIR + name) counts when its known prefix is already inside a per-host
           directory. hostpaths.persistent(x) is the /var name, never a finding.
  shell    a redirection (>, >>, &>) or a writing command (cp, mv, install, ln, mkdir, mktemp, tee, touch, rm,
           chmod, chown, truncate, systemd-creds, ssh-keygen) with an argument that expands to a per-host /etc
           path, through the file's own assignments and ${VAR:-default}
  units    ReadWritePaths=, BindPaths=, ConfigurationDirectory= naming a per-host /etc path, and the Exec*= command
           lines read as shell (sh -c bodies included)
  tmpfiles any line on a per-host /etc path, except 00-regalia-etc.conf's L/L+ line linking it to its /var name
NOT SEEN (a limitation, stated): a path built at run time from data (node.json's "site" is a value read from a file;
enrol._install guards that one itself, by writing only hostpaths' /var names); prose procedures in the .md files
(image/etc-inventory.txt lists the operator's writes)."""

from __future__ import annotations

import ast
import collections
import functools
import os
import re
import shlex
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent
sys.path.insert(0, str(HERE))
sys.path.insert(0, str(ROOT))

from source_lexing import shell_code  # noqa: E402
from deploy.baremetal import hostpaths  # noqa: E402

DEPLOY = ROOT / "deploy"
UNIT_DIRS = (DEPLOY / "baremetal" / "units", DEPLOY / "systemd", DEPLOY / "baremetal" / "initrd")
LINKS = "00-regalia-etc.tmpfiles.conf"

Finding = collections.namedtuple("Finding", "file line path entry how")

UNKNOWN = None   # a segment of a value not known statically


def per_host(text, complete):
    """The PER_HOST entry a resolved value writes to, or None. A partial value counts only if its known prefix is
    already strictly inside a per-host DIRECTORY (CONFIG_DIR + name), never a mere prefix of a name."""
    if not text.startswith("/etc"):
        return None
    if complete:
        path = os.path.normpath(text) if text.startswith("/etc/") else text
        return hostpaths.covering(path)
    for entry in hostpaths.PER_HOST:
        if text.startswith(entry + "/"):
            return entry
    return None


# ------------------------------------------------------------------------------------------------ Python


def _segments_text(segments):
    """(the known prefix, complete?)"""
    out = []
    for s in segments:
        if s is UNKNOWN:
            return "".join(out), False
        out.append(s)
    return "".join(out), True


class Resolver:
    """Static values of str expressions: a value is a set of segment tuples (several assignments, several values)."""

    def __init__(self, modules):
        self.modules = modules        # {module name: {CONST: values}}

    def values(self, node, scope, depth=0):
        if depth > 12:
            return {(UNKNOWN,)}
        v = lambda n: self.values(n, scope, depth + 1)          # noqa: E731
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return {(node.value,)}
        if isinstance(node, ast.Name):
            return scope.get(node.id) or {(UNKNOWN,)}
        if isinstance(node, ast.Attribute) and isinstance(node.value, ast.Name):
            module = scope.get(("module", node.value.id))
            if module is not None and node.attr in self.modules.get(module, {}):
                return self.modules[module][node.attr]
            return {(UNKNOWN,)}
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return {a + b for a in v(node.left) for b in v(node.right)}
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            args = node.right.elts if isinstance(node.right, ast.Tuple) else [node.right]
            results = set()
            for fmt in v(node.left):
                for values in _product([v(a) for a in args]):
                    results.add(_percent(fmt, values))
            return results
        if isinstance(node, ast.JoinedStr):
            parts = []
            for part in node.values:
                parts.append(v(part.value) if isinstance(part, ast.FormattedValue) else v(part))
            return {sum(combo, ()) for combo in _product(parts)}
        if isinstance(node, ast.Call):
            name = _call_name(node)
            if name in ("hostpaths.persistent", "persistent", "stored", "enrol.stored"):
                # the /var name: whatever it was, it is not an /etc path any more
                return {("/var/(persistent)",)}
            if name in ("os.path.join", "posixpath.join") and node.args:
                results = set()
                for combo in _product([v(a) for a in node.args]):
                    joined = ()
                    for i, seg in enumerate(combo):
                        joined = seg if i == 0 or (seg and seg[0] is not UNKNOWN and str(seg[0]).startswith("/")) else joined + ("/",) + seg
                    results.add(joined)
                return results
            if name in ("str", "os.fspath") and node.args:
                return v(node.args[0])
            if name in ("Path", "pathlib.Path", "PurePath") and node.args:
                return self.values(ast.Call(func=ast.Name(id="os.path.join"), args=node.args, keywords=[]), scope, depth + 1) \
                    if len(node.args) > 1 else v(node.args[0])
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Div):         # Path / "x"
            return {a + ("/",) + b for a in v(node.left) for b in v(node.right)}
        if isinstance(node, ast.IfExp):
            return v(node.body) | v(node.orelse)
        if isinstance(node, ast.BoolOp):
            out = set()
            for value in node.values:
                out |= v(value)
            return out
        return {(UNKNOWN,)}


def _product(lists):
    combos = [()]
    for options in lists:
        combos = [c + (o,) for c in combos for o in list(options)[:8]]
        combos = combos[:64]
    return combos


def _percent(fmt, values):
    out, args = [], list(values)
    text_parts = []
    for seg in fmt:
        if seg is UNKNOWN:
            return tuple(out) + (UNKNOWN,)
        text_parts.append(seg)
    pieces = re.split(r"(%[-#0 +]*\d*(?:\.\d+)?[sdrxi%])", "".join(text_parts))
    for piece in pieces:
        if re.fullmatch(r"%[-#0 +]*\d*(?:\.\d+)?[sdrxi%]", piece or "x"):
            if piece == "%%":
                out.append("%")
            elif args:
                out.extend(args.pop(0))
            else:
                out.append(UNKNOWN)
        elif piece:
            out.append(piece)
    return tuple(out)


def _call_name(node):
    f = node.func
    parts = []
    while isinstance(f, ast.Attribute):
        parts.append(f.attr)
        f = f.value
    if isinstance(f, ast.Name):
        parts.append(f.id)
    elif parts:
        parts.append("?")
    return ".".join(reversed(parts))


OS_WRITES = {"mkdir", "makedirs", "rename", "renames", "replace", "link", "symlink", "unlink", "remove", "rmdir",
             "removedirs", "chmod", "chown", "lchown", "mknod", "mkfifo", "truncate", "utime"}
SHUTIL_WRITES = {"copy", "copy2", "copyfile", "copytree", "move", "rmtree", "copymode", "copystat"}
PATH_WRITES = {"write_text", "write_bytes", "touch", "symlink_to", "hardlink_to"}
OWN_WRITERS = {"_install", "_write_private", "_atomic_json", "_atomic_write", "atomic_write", "wg_key",
               "_ensure_trusted_dir", "_safe_directory", "write"}
WRITING_FLAGS = {"O_WRONLY", "O_RDWR", "O_CREAT", "O_TRUNC", "O_APPEND"}
SHELL_WRITERS = {"cp", "mv", "install", "ln", "mkdir", "mktemp", "tee", "touch", "rm", "chmod", "chown", "truncate",
                 "systemd-creds", "ssh-keygen", "rsync", "dd", "sed"}


def _writes(node):
    """How this call writes, or None: (how, [the argument nodes that name the written path])."""
    name = _call_name(node)
    last = name.rsplit(".", 1)[-1]
    args = list(node.args) + [k.value for k in node.keywords if k.arg not in ("data", "text", "content", "encoding", "mode")]
    if name in ("open", "io.open", "builtins.open", "os.fdopen") or (last == "open" and name.endswith("Path.open")):
        mode = node.args[1] if len(node.args) > 1 else next((k.value for k in node.keywords if k.arg == "mode"), None)
        if isinstance(mode, ast.Constant) and isinstance(mode.value, str) and set(mode.value) & set("wax+"):
            return "open(..., %r)" % mode.value, node.args[:1]
        return None
    if name == "os.open":
        flags = node.args[1] if len(node.args) > 1 else None
        names = {n.attr for n in ast.walk(flags) if isinstance(n, ast.Attribute)} if flags is not None else set()
        return ("os.open(%s)" % "|".join(sorted(names & WRITING_FLAGS)), node.args[:1]) if names & WRITING_FLAGS else None
    if name.startswith("os.") and last in OS_WRITES:
        return name, args
    if name.startswith("shutil.") and last in SHUTIL_WRITES:
        return name, args
    if last in PATH_WRITES or (last in ("mkdir", "unlink", "rename", "replace", "chmod", "rmdir") and not name.startswith("os.")):
        receiver = node.func.value if isinstance(node.func, ast.Attribute) else None
        return (name, [receiver] + args) if receiver is not None else None
    if last in OWN_WRITERS:
        if last == "write":                       # host.write(path, text): the path only, never the data
            return (name, node.args[:1]) if node.args else None
        return name, args
    return None


def _argv_writes(node):
    """An argv literal ([cmd, ...]) whose command writes: (how, the argument nodes); a sh -c body: (how, None, text)."""
    if not isinstance(node, (ast.List, ast.Tuple)) or not node.elts:
        return None
    first = node.elts[0]
    if not (isinstance(first, ast.Constant) and isinstance(first.value, str)):
        return None
    command = os.path.basename(first.value)
    words = [e.value if isinstance(e, ast.Constant) and isinstance(e.value, str) else None for e in node.elts[1:]]
    if command in SHELL_WRITERS:
        written = _written_args(command, words)
        return ("argv %s" % command, [node.elts[1 + i] for i in written]) if written else None
    return None


def _written_args(command, words):
    """The indices (into words, the arguments) a writing command writes; words: str, or None where not literal."""
    if command == "systemd-creds":          # only `encrypt` writes, its last argument (decrypt's output is ours to judge too)
        if "encrypt" in words or "decrypt" in words:
            return [len(words) - 1] if words and words[-1] != "/dev/null" and words[-1] != "-" else []
        return []
    if command == "sed":                    # only in place
        return [i for i, w in enumerate(words) if w is None or not w.startswith("-")] if any(
            w and (w == "-i" or w.startswith("-i") or w == "--in-place") for w in words) else []
    return [i for i, w in enumerate(words) if w is None or not w.startswith("-") or "/" in w]


def module_constants(tree, resolver, modules_by_alias):
    scope = dict(modules_by_alias)
    consts = {}
    for stmt in tree.body:
        targets = []
        if isinstance(stmt, ast.Assign):
            targets = [t for t in stmt.targets if isinstance(t, ast.Name)]
            value = stmt.value
        elif isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value is not None:
            targets, value = [stmt.target], stmt.value
        for t in targets:
            values = resolver.values(value, scope)
            if any(seg is not UNKNOWN for vals in values for seg in vals[:1]):
                scope[t.id] = consts[t.id] = values
    return consts


_ALIASES = {}


def _aliases(tree):
    """{("module", local name): deploy module name} for `from deploy.baremetal import x [as y]` and `import ...`."""
    if id(tree) in _ALIASES:
        return _ALIASES[id(tree)][1]
    out = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom) and (node.module or "").startswith("deploy"):
            for a in node.names:
                out[("module", a.asname or a.name)] = a.name
        elif isinstance(node, ast.Import):
            for a in node.names:
                if a.name.startswith("deploy."):
                    out[("module", a.asname or a.name.rsplit(".", 1)[-1])] = a.name.rsplit(".", 1)[-1]
    _ALIASES[id(tree)] = (tree, out)          # the tree is kept alive with it: _parse caches it
    return out


class _Scanner(ast.NodeVisitor):
    def __init__(self, name, resolver, module_scope, findings):
        self.name, self.resolver, self.findings = name, resolver, findings
        self.scopes = [module_scope]

    def _scope(self):
        return self.scopes[-1]

    def visit_FunctionDef(self, node):
        scope = dict(self._scope())
        a = node.args
        positional = a.posonlyargs + a.args
        for arg, default in zip(positional[len(positional) - len(a.defaults):], a.defaults):
            scope[arg.arg] = self.resolver.values(default, self._scope())
        for arg, default in zip(a.kwonlyargs, a.kw_defaults):
            if default is not None:
                scope[arg.arg] = self.resolver.values(default, self._scope())
        for stmt in ast.walk(node):                     # local assignments, all of them (a set of possible values)
            if isinstance(stmt, ast.Assign):
                for t in stmt.targets:
                    if isinstance(t, ast.Name):
                        values = self.resolver.values(stmt.value, scope)
                        if any(seg is not UNKNOWN for vals in values for seg in vals[:1]):
                            scope[t.id] = scope.get(t.id, set()) | values
        self.scopes.append(scope)
        self.generic_visit(node)
        self.scopes.pop()

    visit_AsyncFunctionDef = visit_FunctionDef

    def _judge(self, how, nodes, line):
        for arg in nodes:
            for segments in self.resolver.values(arg, self._scope()):
                text, complete = _segments_text(segments)
                entry = per_host(text, complete)
                if entry:
                    self.findings.append(Finding(self.name, line, text + ("" if complete else "..."), entry, how))

    def visit_Call(self, node):
        found = _writes(node)
        if found:
            self._judge(found[0], found[1], node.lineno)
        for arg in node.args:
            argv = _argv_writes(arg)
            if argv:
                self._judge(argv[0], argv[1], node.lineno)
            if isinstance(arg, (ast.List, ast.Tuple)) and len(arg.elts) >= 3 \
                    and all(isinstance(e, ast.Constant) and isinstance(e.value, str) for e in arg.elts[:2]) \
                    and os.path.basename(arg.elts[0].value) in ("sh", "bash") and arg.elts[1].value == "-c":
                for segments in self.resolver.values(arg.elts[2], self._scope()):
                    text, _ = _segments_text(segments)
                    for f in scan_shell(text, self.name):
                        self.findings.append(f._replace(line=node.lineno, how="sh -c: " + f.how))
        self.generic_visit(node)


@functools.lru_cache(maxsize=None)
def _parse(text):
    return ast.parse(text)          # read only below: one parse per distinct text, for the mutants' many scans


def scan_python_tree(texts, focus=None):
    """{relative path: text} of every deploy module -> findings; in `focus` only (None: all), the constants of all."""
    trees = {}
    for rel, text in texts.items():
        try:
            trees[rel] = _parse(text)
        except SyntaxError as e:
            raise AssertionError("%s does not parse: %s" % (rel, e))
    modules = {}
    resolver = Resolver(modules)
    for _ in range(3):                                # constants that name another module's, to a fixed point
        for rel, tree in trees.items():
            modules[Path(rel).stem] = module_constants(tree, resolver, _aliases(tree))
    findings = []
    for rel, tree in sorted(trees.items()):
        if focus is not None and rel not in focus:
            continue
        scope = dict(_aliases(tree))
        scope.update(modules[Path(rel).stem])
        _Scanner(rel, resolver, scope, findings).visit(tree)
    return findings


# ------------------------------------------------------------------------------------------------ shell

ASSIGN = re.compile(r"(?:^|[\s;])(?:export\s+|local\s+|readonly\s+)?([A-Za-z_][A-Za-z0-9_]*)=(\"[^\"]*\"|'[^']*'|[^\s;&|]*)")
REDIRECT = re.compile(r"(?:\d|&)?>>?\|?\s*(\"[^\"]*\"|'[^']*'|[^\s;&|<>()]+)")
WRAPPERS = {"sudo", "env", "command", "exec", "nice", "nohup", "time", "!", "then", "do", "else", "if", "while", "{", "("}


def _expand(word, variables, assigned):
    """(the known prefix, complete?) of a shell word."""
    if len(word) >= 2 and word[0] == word[-1] and word[0] in "\"'":
        if word[0] == "'":
            return word[1:-1], True
        word = word[1:-1]
    out, complete, i = [], True, 0
    while i < len(word):
        m = re.match(r"\$\{([A-Za-z_][A-Za-z0-9_]*)(?::?-([^}]*))?\}|\$([A-Za-z_][A-Za-z0-9_]*)", word[i:])
        if m:
            name = m.group(1) or m.group(3)
            if name in variables:
                text, whole = variables[name]
                out.append(text)
                if not whole:
                    return "".join(out), False
            elif m.group(2) is not None and name not in assigned:
                text, whole = _expand(m.group(2), variables, assigned)   # ${VAR:-default}: the default, VAR unset
                out.append(text)
                if not whole:
                    return "".join(out), False
            else:
                return "".join(out), False
            i += m.end()
            continue
        if word[i] in "$`*?[":
            return "".join(out), False
        if word[i] == "\\" and i + 1 < len(word):
            out.append(word[i + 1])
            i += 2
            continue
        if word[i] in "\"'":
            i += 1
            continue
        out.append(word[i])
        i += 1
    return "".join(out), complete


def _logical_lines(code):
    lines, current, start = [], "", None
    for number, line in enumerate(code.splitlines(), 1):
        if start is None:
            start = number
        if line.endswith("\\"):
            current += line[:-1] + " "
            continue
        lines.append((start, current + line))
        current, start = "", None
    if current:
        lines.append((start, current))
    return lines


@functools.lru_cache(maxsize=None)
def _scan_shell_cached(text, name):
    return tuple(_scan_shell(text, name))


def scan_shell(text, name):
    return list(_scan_shell_cached(text, name))


def _scan_shell(text, name):
    code = shell_code(text)
    variables, assigned, findings = {}, set(), []
    lines = _logical_lines(code)
    for _, line in lines:
        for m in ASSIGN.finditer(line):
            assigned.add(m.group(1))
    for number, line in lines:
        for m in ASSIGN.finditer(line):
            variables[m.group(1)] = _expand(m.group(2), variables, assigned)

        def judge(word, how):
            text, complete = _expand(word, variables, assigned)
            entry = per_host(text, complete)
            if entry:
                findings.append(Finding(name, number, text + ("" if complete else "..."), entry, how))

        for m in REDIRECT.finditer(line):
            judge(m.group(1), "redirection")
        for command in re.split(r"&&|\|\||[;|]|\$\(|`|\bthen\b|\bdo\b", line):
            try:
                words = shlex.split(command, posix=False)
            except ValueError:
                words = command.split()
            while words and (words[0] in WRAPPERS or re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*=.*", words[0])):
                words = words[1:]
            command_name = os.path.basename(words[0].strip("\"'")) if words else None
            if command_name in SHELL_WRITERS:
                args = words[1:]
                for i in _written_args(command_name, [w.strip("\"'") for w in args]):
                    word = args[i]
                    judge(word.split("=", 1)[1] if word.startswith(("of=", "--target-directory=")) else word, command_name)
    return findings


# ------------------------------------------------------------------------------------------------ units, tmpfiles

UNIT_WRITE_KEYS = ("ReadWritePaths", "BindPaths")
EXEC_KEYS = re.compile(r"^(Exec(?:Start|StartPre|StartPost|Stop|StopPost|Reload|Condition))=(.*)$")


def scan_unit(text, name):
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        line = line.strip()
        if not line or line[0] in "#;":
            continue
        key, _, value = line.partition("=")
        if key in UNIT_WRITE_KEYS:
            for word in value.split():
                path = word.lstrip("-+")
                for part in (path.split(":")[:2] if key == "BindPaths" else [path]):
                    entry = per_host(part, True)
                    if entry:
                        findings.append(Finding(name, number, part, entry, key + "="))
        elif key == "ConfigurationDirectory":
            for word in value.split():
                path = "/etc/" + word.split(":")[0]
                entry = per_host(path, True)
                if entry:
                    findings.append(Finding(name, number, path, entry, key + "="))
        m = EXEC_KEYS.match(line)
        if m:
            command = m.group(2).lstrip("-+!@:|")
            for f in scan_shell(command, name):
                findings.append(f._replace(line=number, how=m.group(1) + "=: " + f.how))
            inner = re.search(r"\bsh -c (['\"])(.*)\1", command)
            if inner:
                for f in scan_shell(inner.group(2), name):
                    findings.append(f._replace(line=number, how=m.group(1) + "= sh -c: " + f.how))
    return findings


def scan_tmpfiles(text, name):
    findings = []
    for number, line in enumerate(text.splitlines(), 1):
        fields = line.split()
        if not fields or fields[0].startswith("#") or len(fields) < 2:
            continue
        kind, path = fields[0], fields[1]
        entry = per_host(path, True)
        if not entry:
            continue
        target = fields[6] if len(fields) > 6 else None
        if Path(name).name == LINKS and kind.rstrip("!") in ("L", "L+") and target == hostpaths.persistent(path):
            continue
        findings.append(Finding(name, number, path, entry, "tmpfiles %s%s" % (kind, " -> %s" % target if target else "")))
    return findings


# ------------------------------------------------------------------------------------------------ the tree


def deploy_files(root=ROOT):
    """{relative path: kind} of every file scanned."""
    out = {}
    for path in sorted((root / "deploy").rglob("*")):
        if not path.is_file() or "__pycache__" in path.parts:
            continue
        rel = str(path.relative_to(root))
        if path.suffix == ".py":
            out[rel] = "python"
        elif path.suffix == ".sh" or (path.parent.name == "initrd" and path.suffix == "" and path.read_bytes()[:2] == b"#!"):
            out[rel] = "shell"
        elif path.name.endswith(".tmpfiles.conf"):
            out[rel] = "tmpfiles"
        elif any(d in path.parents for d in [root / u.relative_to(ROOT) for u in UNIT_DIRS]) and (
                path.suffix in (".service", ".timer", ".path", ".socket", ".mount", ".target")
                or (path.suffix == ".conf" and path.parent.name.endswith((".service.d", ".timer.d", ".path.d", ".socket.d")))):
            out[rel] = "unit"
    return out


def scan(root=ROOT, overrides=None):
    """Every finding in deploy/ (overrides: {relative path: text}, a mutant's)."""
    overrides = overrides or {}
    files = deploy_files(root)
    for rel in overrides:
        files.setdefault(rel, "python" if rel.endswith(".py") else "shell" if rel.endswith(".sh") else
                         "tmpfiles" if rel.endswith(".tmpfiles.conf") else "unit")
    read = lambda rel: overrides[rel] if rel in overrides else (root / rel).read_text(errors="replace")    # noqa: E731
    texts = {rel: read(rel) for rel, kind in files.items() if kind == "python"}
    focus = None
    if overrides:
        # a mutant's scan: the files it changed, and every module that imports a changed module (its constants), in
        # full; the rest are the tree as it is, which the clean scan covers
        changed = {Path(rel).stem for rel in overrides if rel.endswith(".py")}
        focus = set(overrides) | {rel for rel in texts if changed & set(_aliases(_parse(texts[rel])).values())}
    findings = scan_python_tree(texts, focus)
    for rel, kind in sorted(files.items()):
        if focus is not None and rel not in focus:
            continue
        if kind == "shell":
            findings += scan_shell(read(rel), rel)
        elif kind == "unit":
            findings += scan_unit(read(rel), rel)
        elif kind == "tmpfiles":
            findings += scan_tmpfiles(read(rel), rel)
    return sorted(set(findings))


def describe(f):
    return "%s:%d writes %s (%s) by its /etc name: %s is this host's own (hostpaths.PER_HOST) and lives on /var; " \
           "write %s (hostpaths.persistent)" % (f.file, f.line, f.path, f.how, f.entry, hostpaths.VAR_ETC + f.entry[len("/etc"):])


if __name__ == "__main__":
    found = scan()
    for f in found:
        print(describe(f))
    sys.exit(1 if found else 0)
