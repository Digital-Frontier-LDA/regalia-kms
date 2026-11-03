"""A private key handed to a signing tool by file descriptor, never by a path on disk (ADR-0002 D28, #156).

The offline keys (the membership root and the three boot-image signing keys) are software keys: Shamir shares,
reconstructed only in the RAM of the air-gapped ceremony laptop by regalia-ceremony's offline-keys.py, which
runs ONE allowed command with each reconstructed key in a sealed memfd it passes down, its number substituted
for {keyfd:NAME}, and a session ID for {session} (regalia-ceremony#115):

    manifest sign ... --signer root --key-fd {keyfd:root} --offline-session {session}
    uki.py sign ... --initrd-key-fd {keyfd:pcr-initrd} --system-key-fd {keyfd:pcr-system}
                    --secure-boot-key-fd {keyfd:secure-boot} --offline-session {session}

The rules here are the receiving side's:
  * the descriptor is a pipe, or a memfd sealed against writing (F_SEAL_WRITE). A regular file anywhere else is
    refused, a tmpfs one included: a key that was ever a file can be copied, and a sealed memfd is how the
    ceremony passes it;
  * it is read from its offset to EOF, at most MAX_BYTES, into a bytearray, and closed; one PKCS#8 PEM key, unencrypted;
  * the caller zeroes the bytearray (zero) as soon as the key is loaded, and the key itself is never logged or written;
  * the session ID is 32 lowercase hex, and the signing record says "offline-keys session <id>", which the ceremony's
    own record also carries, so each names the other.
WHAT THIS DOES NOT PROVE. A pipe is accepted (offline-keys.py may use one), and a pipe cannot show where its bytes came
from: `cat key.pem | ... --key-fd 0` from a file on disk passes here. That a key was never on disk is guaranteed by the
ceremony's session routine (offline-keys.py reconstructs it in RAM and hands it over), not by this check; the check
only refuses the plainly wrong thing, a file descriptor of a file. Likewise for copies in memory: the bytearray is
zeroed, but loading the key makes an immutable `bytes` copy (load_pem_private_key(bytes(buffer))) and the library
keeps its own key object; neither can be cleared from Python, and both live until the process exits, seconds later.
The ceremony laptop's RAM is the boundary, and it is powered off after the session."""
import fcntl
import os
import re
import stat

from deploy.baremetal.membership import Refused, require

MAX_BYTES = 16 * 1024


def _is_memfd(fd):
    try:
        return os.readlink("/proc/self/fd/%d" % fd).startswith("/memfd:")
    except OSError:
        return False


def read(fd, what):
    """The key behind descriptor `fd`, as a bytearray, the descriptor closed. Refused (and closed) unless it is a pipe
    or a write-sealed memfd."""
    require(isinstance(fd, int) and not isinstance(fd, bool) and fd > 2, "%s: a descriptor number above 2" % what)
    try:
        info = os.fstat(fd)
    except OSError as error:
        raise Refused("%s: descriptor %d is not open (%s)" % (what, fd, error.strerror)) from None
    try:
        if stat.S_ISFIFO(info.st_mode):
            pass
        elif stat.S_ISREG(info.st_mode) and _is_memfd(fd):
            seals = fcntl.fcntl(fd, fcntl.F_GET_SEALS)
            require(seals & fcntl.F_SEAL_WRITE, "%s: the memfd is not sealed against writing" % what)
        else:
            raise Refused("%s: descriptor %d is not a pipe or a sealed memfd: a key is never read from a file on disk" % (what, fd))
        buffer = bytearray()
        while len(buffer) <= MAX_BYTES:
            chunk = os.read(fd, 4096)
            if not chunk:
                break
            buffer += chunk
        if len(buffer) > MAX_BYTES:
            zero(buffer)
            raise Refused("%s: more than %d bytes: not one key" % (what, MAX_BYTES))
        require(buffer, "%s: descriptor %d holds nothing" % (what, fd))
        return buffer
    finally:
        os.close(fd)


def zero(buffer):
    """Overwrite a bytearray in place (the one copy this module holds)."""
    if isinstance(buffer, bytearray):
        buffer[:] = bytes(len(buffer))


def session(value):
    """The offline-keys session ID, as the signing records carry it."""
    require(isinstance(value, str) and re.fullmatch(r"[0-9a-f]{32}", value) is not None, "--offline-session is 32 lowercase hex")
    return "offline-keys session %s" % value


def sealed_memfd(buffer, name="regalia-key"):
    """`buffer` in a new memfd, sealed (no write, grow, shrink or further seal) and rewound: what a tool that reads a
    key by path is given, as /dev/fd/N with the descriptor passed down. The caller closes it."""
    fd = os.memfd_create(name, os.MFD_CLOEXEC | os.MFD_ALLOW_SEALING)
    try:
        view, done = memoryview(buffer), 0
        while done < len(buffer):
            done += os.write(fd, view[done:])
        fcntl.fcntl(fd, fcntl.F_ADD_SEALS, fcntl.F_SEAL_WRITE | fcntl.F_SEAL_GROW | fcntl.F_SEAL_SHRINK | fcntl.F_SEAL_SEAL)
        os.lseek(fd, 0, os.SEEK_SET)
        return fd
    except BaseException:
        os.close(fd)
        raise


def tty_secret(prompt, what, limit=256, tty="/dev/tty"):
    """A secret typed at this process's controlling terminal, echo off, as a bytearray: refused without a terminal, and
    never read from standard input (getpass falls back to stdin, with echo, when /dev/tty cannot be opened). `what`
    names it in a refusal ("the PIN")."""
    import termios
    try:
        fd = os.open(tty, os.O_RDWR | os.O_NOCTTY)
    except OSError as error:
        raise Refused("%s is typed at the console: no controlling terminal (%s)" % (what, error.strerror)) from None
    typed = bytearray()
    try:
        require(os.isatty(fd), "%s is typed at the console: %s is not a terminal" % (what, tty))
        old = termios.tcgetattr(fd)
        new = list(old)
        new[3] &= ~(termios.ECHO | termios.ECHONL)
        termios.tcsetattr(fd, termios.TCSAFLUSH, new)      # echo off and typeahead dropped, THEN the prompt
        try:
            os.write(fd, prompt.encode())
            while len(typed) <= limit:
                chunk = os.read(fd, 1)
                if not chunk or chunk in (b"\n", b"\r"):
                    break
                typed += chunk
        finally:
            termios.tcsetattr(fd, termios.TCSAFLUSH, old)
            os.write(fd, b"\n")
        require(len(typed) <= limit, "%s is longer than %d bytes" % (what, limit))
        require(typed, "no %s was typed" % what)
        return typed
    except BaseException:
        zero(typed)
        raise
    finally:
        os.close(fd)


def tty_line(prompt):
    """A line typed at this process's controlling terminal (stdin is the ceremony's /dev/null): refused without one."""
    try:
        fd = os.open("/dev/tty", os.O_RDWR | os.O_NOCTTY)
    except OSError as error:
        raise Refused("the confirmation is typed at the console: no controlling terminal (%s)" % error.strerror) from None
    try:
        os.write(fd, prompt.encode())
        typed = bytearray()
        while len(typed) <= 256:
            chunk = os.read(fd, 1)
            if not chunk or chunk in (b"\n", b"\r"):
                break
            typed += chunk
        return typed.decode("utf-8", "replace")
    finally:
        os.close(fd)
