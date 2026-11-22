const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const os = require('node:os');
const path = require('node:path');
const { test } = require('node:test');

const root = path.resolve(__dirname, '../..');
const runtime = path.join(process.env.RUNNER_TEMP, 'openspec-ci');
const { parse } = require(path.join(runtime, 'node_modules/yaml'));
const workflow = parse(fs.readFileSync(path.join(root, '.github/workflows/ci.yml'), 'utf8'));
const steps = workflow.jobs['build-test'].steps;
const gate = steps.find(step => step.id === 'openspec-checks');
const revision = '0a32a901d1240eec51ddff323274e2ad935116f3';
const tree = '347cc36bd44945fcff8a6624237222cb64c0cf17';
const checkout = 'actions/checkout@3d3c42e5aac5ba805825da76410c181273ba90b1';
const python = 'actions/setup-python@5fda3b95a4ea91299a34e894583c3862153e4b97';

function fixture(t) {
    const directory = fs.mkdtempSync(path.join(os.tmpdir(), 'openspec-wiring-'));
    t.after(() => fs.rmSync(directory, { recursive: true, force: true }));
    return directory;
}
function write(file, text) {
    fs.mkdirSync(path.dirname(file), { recursive: true });
    fs.writeFileSync(file, text, { mode: 0o700 });
}
function invoke(command, args, env = {}) {
    const result = spawnSync(command, args, {
        cwd: root, encoding: 'utf8', timeout: 10000, env: { ...process.env, ...env },
    });
    assert.ifError(result.error);
    assert.equal(result.signal, null);
    return result;
}

test('required tail uses the immutable product checkout and preserves aggregate participation', () => {
    assert.deepEqual(workflow.permissions, { contents: 'read' });
    assert.ok(workflow.jobs['ci-gate'].needs.includes('build-test'));
    const actual = steps.slice(-6);
    assert.deepEqual(actual.map(step => step.id), ['openspec-source-reserve', 'openspec-product-checkout',
        'openspec-source-verify', 'openspec-python', 'openspec-install', 'openspec-checks']);
    assert.equal(workflow.jobs['build-test']['continue-on-error'], undefined);
    for (const step of actual) {
        assert.equal(step.if, undefined, step.id + ' must run when prior checks pass');
        assert.equal(step['continue-on-error'], undefined, step.id + ' must be required');
    }
    assert.equal(actual[0].run, 'bash tools/openspec-ci/check-source.sh reserve');
    assert.equal(actual[1].uses, checkout);
    assert.equal(actual[1].with.ref, revision, 'wrong immutable product checkout');
    assert.deepEqual(actual[1].with, {
        repository: '$' + '{{ github.repository }}', ref: revision, path: '.openspec-product-source',
        'fetch-depth': 1, 'fetch-tags': false, lfs: false, submodules: false, 'persist-credentials': false,
    });
    assert.equal(actual[2].run, 'bash tools/openspec-ci/check-source.sh verify ' + revision + ' ' + tree);
    assert.equal(actual[3].uses, python);
    assert.deepEqual(actual[3].with, { 'python-version': '3.14.7', architecture: 'x64', 'check-latest': false });
    assert.equal(actual[4].run, 'bash tools/openspec-ci/install-runtime.sh');
    assert.equal(gate.shell, 'bash');
    assert.deepEqual(gate.env, { OPENSPEC_PRODUCT_REVISION: revision, OPENSPEC_PRODUCT_TREE: tree });
});

function runGate(t, phase = '') {
    const temp = fixture(t);
    const rt = path.join(temp, 'openspec-ci');
    const bin = path.join(temp, 'bin');
    const argvLog = path.join(temp, 'trace');
    write(path.join(rt, 'node/bin/node'), [
        '#!/bin/bash', 'set -eu',
        'if [[ "$1" == --test ]]; then',
        '  [[ "$2" == tools/openspec-ci/wiring.test.cjs && "$#" == 2 ]]',
        '  phase=wiring',
        'else',
        '  [[ "$1" == "$RUNNER_TEMP/openspec-ci/node_modules/@fission-ai/openspec/bin/openspec.js" ]]',
        '  shift',
        '  [[ "$*" == "validate --all --strict --no-interactive --json" ]]',
        '  phase=strict',
        'fi',
        'echo "$phase" >> "$CI_FIXTURE_LOG"',
        '[[ "$phase" != "$CI_FIXTURE_FAIL" ]] || exit 41',
        '',
    ].join('\n'));
    write(path.join(bin, 'python3'), [
        '#!/bin/bash', 'set -eu',
        'if [[ "$1" == --version ]]; then',
        '  if [[ "$CI_FIXTURE_FAIL" == python-version ]]; then',
        '    echo python-version >> "$CI_FIXTURE_LOG"',
        '    echo "Python 3.14.8"',
        '  else',
        '    echo "Python 3.14.7"',
        '  fi',
        '  exit 0',
        'fi',
        '[[ "$1" == -BEs ]]',
        'shift',
        'case "$1" in',
        '  -m) [[ "$*" == "-m unittest discover -v -s tests -p test_check_openspec_references.py" ]]; phase=tests ;;',
        '  tools/check_openspec_references.py)',
        '    [[ "$#" == 7 && "$2" == --snapshot && "$3" == "$GITHUB_WORKSPACE" ]]',
        '    [[ "$4" == --source-repo && "$5" == "$GITHUB_WORKSPACE/.openspec-product-source" ]]',
        '    [[ "$6" == --source-revision && "$7" == "$OPENSPEC_PRODUCT_REVISION" ]]',
        '    phase=reference ;;',
        '  tools/openspec-ci/check-result.py)',
        '    [[ "$2" == "$RUNNER_TEMP/openspec-ci/references.json" ]]',
        '    [[ "$3" == "$OPENSPEC_PRODUCT_REVISION" && "$4" == "$OPENSPEC_PRODUCT_TREE" ]]',
        '    phase=envelope ;;',
        '  *) exit 98 ;;',
        'esac',
        'echo "$phase" >> "$CI_FIXTURE_LOG"',
        '[[ "$phase" != "$CI_FIXTURE_FAIL" ]] || exit 42',
        'if [[ "$phase" == reference ]]; then echo \'{"referenceIntegrity":true}\'; fi',
        '',
    ].join('\n'));
    const result = invoke('bash', ['-c', gate.run], {
        ...gate.env, PATH: bin + path.delimiter + process.env.PATH, RUNNER_TEMP: temp,
        GITHUB_WORKSPACE: root, CI_FIXTURE_FAIL: phase, CI_FIXTURE_LOG: argvLog,
    });
    return { result, trace: fs.readFileSync(argvLog, 'utf8').trim().split('\n') };
}

test('mismatched Python pin fails before any OpenSpec command', t => {
    const { result, trace } = runGate(t, 'python-version');
    assert.equal(result.status, 1);
    assert.deepEqual(trace, ['python-version']);
});

const phases = ['strict', 'tests', 'wiring', 'reference', 'envelope'];
test('actual check step runs strict validation, focused tests and the reference envelope in order', t => {
    const { result, trace } = runGate(t);
    assert.equal(result.status, 0, result.stderr);
    assert.deepEqual(trace, phases, 'missing or reordered required check');
});
for (const phase of phases) {
    test('actual check step fails closed when ' + phase + ' fails', t => {
        const { result, trace } = runGate(t, phase);
        assert.equal(result.status, ['strict', 'wiring'].includes(phase) ? 41 : 42,
            'the required phase status must propagate: ' + phase);
        assert.deepEqual(trace, phases.slice(0, phases.indexOf(phase) + 1));
    });
}

test('reference result requires integrity, fixed boundary fields and the exact product pin', t => {
    const temp = fixture(t);
    const output = path.join(temp, 'output.json');
    const good = { referenceIntegrity: true, verificationAuthority: 'not-assessed', coverageComplete: false,
        productSourceRevision: revision, productSourceTree: tree };
    for (const [field, wrong] of [[null, null], ['referenceIntegrity', 'true'], ['verificationAuthority', 'approved'],
        ['coverageComplete', true], ['productSourceRevision', 'wrong'], ['productSourceTree', 'wrong']]) {
        write(output, JSON.stringify(field ? { ...good, [field]: wrong } : good));
        const result = invoke('python3', ['-BEs', 'tools/openspec-ci/check-result.py', output, revision, tree]);
        assert.equal(result.status, field ? 1 : 0, String(field));
        if (field) assert.match(result.stderr, /required integrity envelope and product pin/);
    }
});

function runSource(t, branch, { collision = false, absent = false, failure = '' } = {}) {
    const ws = fixture(t);
    const product = path.join(ws, '.openspec-product-source');
    const git = path.join(ws, 'bin/git');
    fs.mkdirSync(path.join(ws, '.git'));
    if (collision) fs.symlinkSync('nonexistent', product);
    if (!absent && !collision && branch === 'verify') fs.mkdirSync(path.join(product, '.git'), { recursive: true });
    write(git, [
        '#!/bin/bash', 'set -eu',
        '[[ "$GIT_NO_LAZY_FETCH" == 1 && "$GIT_NO_REPLACE_OBJECTS" == 1 && "$GIT_OPTIONAL_LOCKS" == 0 ]]',
        '[[ "$GIT_TERMINAL_PROMPT" == 0 && -v GIT_ALLOW_PROTOCOL && -z "$GIT_ALLOW_PROTOCOL" && ! -v GIT_DIR ]]',
        'echo verified-local-env >> "$GITHUB_WORKSPACE/calls"',
        '[[ "$1" == -C ]]',
        'case "$2:$3:$4" in',
        '  "$GITHUB_WORKSPACE:rev-parse:--verify")',
        '    [[ "$CI_FIXTURE_FAIL" != primary ]] && echo "$GITHUB_SHA" || echo another-head ;;',
        '  */.openspec-product-source:rev-parse:--show-toplevel) echo "$2" ;;',
        '  */.openspec-product-source:rev-parse:--verify)',
        '    if [[ "$5" == HEAD ]]; then',
        '      [[ "$CI_FIXTURE_FAIL" != revision ]] && echo "$CI_FIXTURE_REVISION" || echo another-revision',
        '    else',
        '      [[ "$5" == "$CI_FIXTURE_REVISION^{tree}" ]]',
        '      [[ "$CI_FIXTURE_FAIL" != tree ]] && echo "$CI_FIXTURE_TREE" || echo wrong-tree',
        '    fi ;;',
        '  */.openspec-product-source:cat-file:-t)',
        '    [[ "$5" == "$CI_FIXTURE_REVISION" && "$CI_FIXTURE_FAIL" != unavailable ]]',
        '    [[ "$CI_FIXTURE_FAIL" != type ]] && echo commit || echo tag ;;',
        '  *) exit 99 ;;',
        'esac',
        '',
    ].join('\n'));
    const result = invoke('bash', ['tools/openspec-ci/check-source.sh', branch, revision, tree], {
        PATH: path.dirname(git) + path.delimiter + process.env.PATH, GITHUB_WORKSPACE: ws, GITHUB_SHA: 'workflow-head',
        GIT_DIR: 'bad-original-env', CI_FIXTURE_FAIL: failure, CI_FIXTURE_REVISION: revision, CI_FIXTURE_TREE: tree,
    });
    return { result, accessedGit: fs.existsSync(path.join(ws, 'calls')) };
}

test('product checkout reservation refuses even a dangling symlink', t => {
    assert.equal(runSource(t, 'reserve').result.status, 0);
    const { result, accessedGit } = runSource(t, 'reserve', { collision: true });
    assert.equal(result.status, 1);
    assert.match(result.stderr, /reserved product source directory already exists/);
    assert.equal(accessedGit, false);
});

test('source preparation checks locally with lazy fetch and inherited Git config disabled', t => {
    const { result, accessedGit } = runSource(t, 'verify');
    assert.equal(result.status, 0, result.stderr);
    assert.ok(accessedGit);
    assert.match(result.stdout, /source preflight passed/);
});

for (const [failure, message] of [
    ['missing', /missing separate product Git checkout/],
    ['primary', /primary checkout HEAD differs/], ['revision', /product checkout HEAD differs/],
    ['unavailable', /not a locally available commit/], ['type', /not a locally available commit/],
    ['tree', /commit tree does not match/],
]) {
    test('source preparation refuses ' + failure, t => {
        const { result, accessedGit } = runSource(t, 'verify', { failure, absent: failure === 'missing' });
        assert.equal(result.status, 1, result.stderr);
        assert.match(result.stderr, message);
        assert.equal(accessedGit, failure !== 'missing');
        assert.doesNotMatch(result.stdout, /preflight passed/);
    });
}

test('npm lock checks enforce top pins and deny unapproved downloadable inputs', t => {
    const temp = fixture(t);
    const manifest = path.join(__dirname, 'package.json');
    const lock = JSON.parse(fs.readFileSync(path.join(__dirname, 'package-lock.json'), 'utf8'));
    const lockFile = path.join(temp, 'lock.json');
    for (const [field, value, reason] of [[null, null, null],
        ['version', '99.0.0', /npm pin mismatch: @fission-ai\/openspec version/],
        ['resolved', 'https://example.invalid/other.tgz', /unapproved npm tarball/],
        ['integrity', '', /missing npm integrity/]]) {
        const input = structuredClone(lock);
        if (field) input.packages[field === 'version' ? 'node_modules/@fission-ai/openspec' : 'node_modules/chalk'][field] = value;
        write(lockFile, JSON.stringify(input));
        const result = invoke(process.execPath, [path.join(__dirname, 'check-lock.cjs'), manifest, lockFile]);
        assert.equal(result.status, field ? 1 : 0, result.stderr);
        if (reason) assert.match(result.stderr, reason);
    }
});
