"""Node metrics (#305): what each service on a node publishes for node_exporter's textfile collector.

ONE REGISTRY. METRICS names every regalia_* series a node writes: its type, its help text, its labels and
the writer that owns it, like trails.TRAILS for the audit trails. `write()` refuses a name, a label or a
writer the registry does not list, so a series cannot appear (or be renamed) without this file changing,
and the alert rules (deploy/monitoring/regalia-node.rules.yml, held to this registry by a test) cannot drift
from what is written.

WHERE. Each writer has a directory of its own under RUN_DIR, made by regalia.tmpfiles.conf: owned by the
writer, group GROUP, mode 2750 (no two writers' files share a name, should node_exporter label them by basename): the directory is the control, nobody outside the group reaches a file in it (the
Go shipper's are 0644, these 0640). The setgid bit gives every file the group, so a writer needs no membership;
node_exporter is the group's only other member, through its unit (units/prometheus-node-exporter.service.d:
SupplementaryGroups=regalia-metrics; the package keeps its own user) and can read, not write. No
writer can replace another's file, and node_exporter sees nothing of a writer's state directory. node_exporter
reads them all with one flag, `--collector.textfile.directory=/run/regalia-metrics/*` (a glob, node_exporter
1.9), and it is scraped from the site's monitoring zone over mutual TLS (node_exporter_args, firewall.py).

NOTHING SECRET, NOTHING FROM A PEER (regalia-kms-24). Labels are enums and the values numbers: no key, no
node secret, no text a peer chose. A label value must match LABEL_VALUE and, where the registry lists its
allowed values, be one of them; a free-text reason (authtime's, admission's) goes to that service's audit
trail, never into a label.

STALENESS. node_exporter exports node_textfile_mtime_seconds per file: a writer that stops is an alert on
the file's age (RegaliaNodeMetricsStale), with no heartbeat series of our own.

Writes are whole: rendered, written to a hidden temporary file (the collector reads *.prom only), fsynced,
made 0640, renamed. A metric that cannot be written does not stop the service that writes it: `publish()`
returns False and the file's age raises the alert."""
import contextlib
import math
import os
import re
import tempfile

RUN_DIR = "/run/regalia-metrics"
GROUP = "regalia-metrics"
MODE = 0o640
LABEL_VALUE = re.compile(r"[a-z0-9][a-z0-9_.-]{0,63}")
NAME = re.compile(r"regalia_[a-z0-9_]+")

# authtime's reason, as an enum (the reason itself goes to the time trail). First match wins.
TIME_CAUSES = (
    ("leap", "no_leap_zone"), ("could not be recorded", "unrecorded"), ("could not be asked", "chrony_unreachable"),
    ("not synchronised", "not_synchronised"), ("nobody declared", "undeclared_source"), ("without NTS", "undeclared_source"),
    ("agree", "too_few_sources"), ("source(s)", "too_few_sources"), ("no time source is selected", "too_few_sources"),
)
TIME_CAUSE_VALUES = ("ok", "no_leap_zone", "unrecorded", "chrony_unreachable", "not_synchronised", "undeclared_source",
                     "too_few_sources", "other")
UNLOCK_CAUSES = ("rate", "connections")     # regalia-kms-48's #70 PR 3: refusals before any work is done

# writer: (its directory under RUN_DIR, its files; None: one per trail)
WRITERS = {
    "authtime": ("authtime", ("authtime.prom",)),
    # the heartbeat watch's, and the unlock listener's refusal counter (#317)
    "sync": ("sync", ("heartbeat.prom", "unlock.prom", "membership.prom")),     # membership.prom: the anchor's lag (#66 B3)
    "admission": ("admission", ("lease.prom",)),
    # regalia-esp-advance (root): its own view of the anchor, not sync's (regalia-kms-48: sync parses peers' input)
    "esp-advance": ("esp-advance", ("esp-advance.prom",)),      # not admission.prom: a trail is called admission (its shipper's file)
    "audit-ship": ("audit-ship", None),     # one file per trail: <trail>.prom (cmd/regalia-audit-ship -metrics)
}

# name: (type, help, {label: allowed values or None (any LABEL_VALUE)}, writer)
METRICS = {
    "regalia_time_authenticated": ("gauge", "1 while this node's time is authenticated (authtime.py), else 0; cause says why not.",
                                   {"cause": TIME_CAUSE_VALUES}, "authtime"),
    "regalia_chrony_latch_set": ("gauge", "1 while the chrony latch keeps chronyd stopped: an operator must run regalia-node time-clear.",
                                 {}, "authtime"),
    # heartbeat_watch.metrics() writes these five (the file is moved, the names are not)
    "regalia_heartbeat_seconds_left": ("gauge", "Seconds until this peer's freshness heartbeat expires; 0 with none usable.", {}, "sync"),
    "regalia_heartbeat_live": ("gauge", "1 while this peer may authorize on its heartbeat, else 0.", {}, "sync"),
    "regalia_heartbeat_lifetime_seconds": ("gauge", "Lifetime of the heartbeat held (expiry less issue); 0 with none usable.", {}, "sync"),
    "regalia_heartbeat_max_lifetime_seconds": ("gauge", "The longest heartbeat the current manifest allows; 0 with no manifest.", {}, "sync"),
    "regalia_heartbeat_checked_timestamp_seconds": ("gauge", "When this file was written.", {}, "sync"),
    "regalia_unlock_refused_total": ("counter", "Unlock requests refused before any work was done, by cause.",
                                     {"cause": UNLOCK_CAUSES}, "sync"),
    # #66 B3: sync holds and publishes the chain, the ESP advance anchors it; a lasting gap is an ESP advance that fails
    "regalia_membership_epoch": ("gauge", "The epoch of the membership chain this node's sync holds and publishes.", {}, "sync"),
    # #432 step 2d: activation by quorum, this node's own view (sync)
    "regalia_activation_holder": ("gauge", "1 when this node holds an unexpired activation lease for itself (#432).", {}, "sync"),
    "regalia_activation_lease_expires_seconds": ("gauge", "When this node's own activation lease expires (unix seconds), 0 when it holds "
                                                 "none.", {}, "sync"),
    "regalia_activation_recovery_active": ("gauge", "1 while an owner recovery authorization holds on this node: it activates its "
                                           "site alone, the other nodes quarantined (#432 amendment 5).", {}, "sync"),
    "regalia_membership_anchor_epoch": ("gauge", "The epoch of the TPM anchor: the last chain regalia-esp-advance wrote to the ESP "
                                        "and anchored. Rollback protection stands at this epoch.", {}, "sync"),
    # #66 B3, written by regalia-esp-advance itself (root) at every run, success or not
    "regalia_esp_advance_ok": ("gauge", "1 when regalia-esp-advance's last run wrote the ESP and anchored it, 0 when it failed.",
                               {}, "esp-advance"),
    "regalia_esp_anchor_epoch": ("gauge", "The TPM anchor's epoch as regalia-esp-advance read it at its last run.", {}, "esp-advance"),
    "regalia_esp_boot_renderable": ("gauge", "1 when the initrd can render a boot configuration from the chain on the ESP; 0: the "
                                    "next boot asks for the recovery key.", {}, "esp-advance"),
    "regalia_esp_advance_run_timestamp_seconds": ("gauge", "When regalia-esp-advance last ran.", {}, "esp-advance"),
    "regalia_admission_serving": ("gauge", "1 while this node holds a runtime lease that lets the KMS daemon serve, else 0.",
                                  {}, "admission"),
    "regalia_admission_lease_seconds_left": ("gauge", "Seconds left on the runtime lease held; 0 with none.", {}, "admission"),
    # cmd/regalia-audit-ship's writeMetrics (regalia-kms-48; a test holds the Go source to these names). Its `trail`
    # label never passes through render(): it is the unit instance's name (%i), one of trails.TRAILS
    "regalia_audit_trail_lines": ("gauge", "Complete lines in the trail file.", {"trail": None}, "audit-ship"),
    "regalia_audit_trail_committed": ("gauge", "Lines the collector has committed.", {"trail": None}, "audit-ship"),
    "regalia_audit_trail_backlog": ("gauge", "Lines not yet committed at the collector.", {"trail": None}, "audit-ship"),
    "regalia_audit_trail_tampered": ("gauge", "1 when the file no longer holds what the collector committed: shipping stopped.",
                                     {"trail": None}, "audit-ship"),
    "regalia_audit_trail_last_success_seconds": ("gauge", "When a pass last committed everything.", {"trail": None}, "audit-ship"),
}


class Refused(ValueError):
    pass


def time_cause(reason):
    """authtime's free-text reason as a TIME_CAUSE_VALUES enum: "ok" for none."""
    if not reason:
        return "ok"
    for needle, cause in TIME_CAUSES:
        if needle in reason:
            return cause
    return "other"


def render(writer, samples):
    """The textfile for `writer`: samples are (name, {label: value}, number). Every name, label and value is
    checked against the registry; the text is deterministic (names, then label sets, in sorted order)."""
    if writer not in WRITERS:
        raise Refused("no metrics writer is called %r" % (writer,))
    by_name = {}
    for name, labels, value in samples:
        if name not in METRICS or not NAME.fullmatch(name):
            raise Refused("%r is not a registered metric" % (name,))
        kind, _, allowed, owner = METRICS[name]
        if owner != writer:
            raise Refused("%s is written by %s, not %s" % (name, owner, writer))
        if set(labels) != set(allowed):
            raise Refused("%s takes the labels %s, not %s" % (name, sorted(allowed), sorted(labels)))
        for label, given in labels.items():
            if not (isinstance(given, str) and LABEL_VALUE.fullmatch(given)) or (allowed[label] is not None and given not in allowed[label]):
                raise Refused("%s{%s=%r} is not an allowed value" % (name, label, given))
        if isinstance(value, bool) or not isinstance(value, (int, float)) or not math.isfinite(value):
            raise Refused("%s has no number" % name)
        if kind == "counter" and value < 0:
            raise Refused("%s is a counter and cannot be negative" % name)
        by_name.setdefault(name, {})[tuple(sorted(labels.items()))] = value
    lines = []
    for name in sorted(by_name):
        kind, text, _, _ = METRICS[name]
        lines += ["# HELP %s %s" % (name, text), "# TYPE %s %s" % (name, kind)]
        for labels, value in sorted(by_name[name].items()):
            shown = "{%s}" % ",".join('%s="%s"' % pair for pair in labels) if labels else ""
            lines.append("%s%s %s" % (name, shown, int(value) if float(value).is_integer() else repr(float(value))))
    return "\n".join(lines) + "\n"


def path(writer, name=None, run_dir=RUN_DIR):
    """The file `name` of `writer` (the only one, when it has one), in its directory."""
    directory, files = WRITERS[writer]
    if name is None:
        if not files or len(files) != 1:
            raise Refused("%s writes several files: name one" % writer)
        name = files[0]
    elif files is not None and name not in files:
        raise Refused("%s writes no file called %s" % (writer, name))
    return os.path.join(run_dir, directory, name)


class Counter:
    """A counter by cause (the unlock listener's refusals, #317). Counting is an increment under a lock and
    nothing else: a refusal flood must not become a disk-write flood on the refusing thread (the accept loop,
    for "connections"; regalia-kms-48). flush() publishes it whole, at start and on the owner's round, and
    never raises; one lock spans the snapshot and the write, so two flushes cannot publish out of order and
    make the counter go backwards (which Prometheus would read as a reset)."""

    def __init__(self, writer, name, file, causes, publish=None):
        import threading
        self.writer, self.name, self.file = writer, name, file
        self.counts, self.lock, self.publishing = {cause: 0 for cause in causes}, threading.Lock(), threading.Lock()
        self.publish = publish or (lambda samples: globals()["publish"](writer, samples, path(writer, file)))

    def samples(self):
        return [(self.name, {"cause": cause}, count) for cause, count in sorted(self.counts.items())]

    def flush(self):
        with self.publishing:
            with self.lock:
                samples = self.samples()
            try:
                self.publish(samples)
            except Exception:             # noqa: BLE001 - metrics never stop what counts
                pass

    def __call__(self, cause):
        """One refusal of `cause`: counted, not written (flush() writes, from the owner's round)."""
        with self.lock:
            if cause in self.counts:
                self.counts[cause] += 1


def write(target, text):
    """Replace `target` whole: a hidden temporary file in the same directory, fsynced, 0640, renamed."""
    directory = os.path.dirname(os.path.abspath(target))
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".metrics-", suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            f.write(text)
            f.flush()
            os.fchmod(f.fileno(), MODE)
            os.fsync(f.fileno())
        os.replace(tmp, target)
    except BaseException:
        with contextlib.suppress(FileNotFoundError):
            os.unlink(tmp)
        raise


def publish(writer, samples, target=None, run_dir=RUN_DIR):
    """render() then write(); False (and nothing raised) when the file cannot be written: metrics never stop the
    service, and RegaliaNodeMetricsStale sees the file stop moving. A sample the registry refuses still raises."""
    text = render(writer, samples)
    try:
        write(target or path(writer, run_dir=run_dir), text)
        return True
    except OSError:
        return False


def node_exporter_args(cfg, port=None, web_config="/etc/regalia/node-exporter/web.yml"):
    """ARGS for node_exporter (Debian's /etc/default/prometheus-node-exporter), from the validated site config: it
    listens on host_ipv4 only, behind mutual TLS (web.yml), and reads the writers' directories. Its default
    collectors are kept (the processes collector, which would read command lines, is off by default)."""
    from deploy.baremetal import sitecfg
    port = sitecfg.NODE_EXPORTER_PORT if port is None else port
    return ("--web.listen-address=%s:%d --web.config.file=%s --collector.textfile.directory=%s/*"
            % (cfg["host_ipv4"], port, web_config, RUN_DIR))


def main(argv=None):
    """`python3 -Es -m deploy.baremetal.metrics node-exporter-args SITE.json`: the ARGS line for Debian's
    /etc/default/prometheus-node-exporter on this host."""
    import argparse
    import json
    import sys
    from deploy.baremetal import sitecfg
    parser = argparse.ArgumentParser(description=main.__doc__.splitlines()[0])
    parser.add_argument("what", choices=("node-exporter-args",))
    parser.add_argument("site")
    args = parser.parse_args(argv)
    try:
        with open(args.site) as f:
            cfg = sitecfg.validate(json.load(f))
    except (OSError, ValueError) as failure:
        print("REFUSED: %s" % failure, file=sys.stderr)
        return 2
    print('ARGS="%s"' % node_exporter_args(cfg))
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(main())
