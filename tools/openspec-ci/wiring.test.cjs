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
const toolingPresent = '$' + '{{ steps.openspec-tooling-plan.outputs.present }}';
const toolingRevision = '$' + '{{ steps.openspec-tooling-plan.outputs.revision }}';
const toolingTree = '$' + '{{ steps.openspec-tooling-plan.outputs.tree }}';
const byId = id => steps.find(step => step.id === id);
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
    const actual = steps.slice(-10);
    assert.deepEqual(actual.map(step => step.id), ['openspec-source-reserve', 'openspec-product-checkout',
        'openspec-source-verify', 'openspec-python', 'openspec-tooling-plan', 'openspec-tooling-reserve',
        'openspec-tooling-checkout', 'openspec-tooling-verify', 'openspec-install', 'openspec-checks']);
    assert.equal(workflow.jobs['build-test']['continue-on-error'], undefined);
    for (const step of actual) {
        const conditional = ['openspec-tooling-reserve', 'openspec-tooling-checkout',
            'openspec-tooling-verify'].includes(step.id);
        assert.equal(step.if, conditional ? "steps.openspec-tooling-plan.outputs.present == 'true'" : undefined);
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
    assert.equal(actual[4].run, 'python3 -BEs tools/openspec-ci/plan-tooling-source.py "$GITHUB_WORKSPACE" "$GITHUB_OUTPUT"');
    assert.equal(actual[5].run, 'bash tools/openspec-ci/check-source.sh reserve-tooling');
    assert.equal(actual[6].uses, checkout);
    assert.deepEqual(actual[6].with, {
        repository: '$' + '{{ github.repository }}', ref: toolingRevision, path: '.openspec-tooling-source',
        'fetch-depth': 1, 'fetch-tags': false, lfs: false, submodules: false, 'persist-credentials': false,
    });
    assert.deepEqual(actual[7].env, { OPENSPEC_TOOLING_REVISION: toolingRevision, OPENSPEC_TOOLING_TREE: toolingTree });
    assert.equal(actual[7].run, 'bash tools/openspec-ci/check-source.sh verify-tooling "$OPENSPEC_TOOLING_REVISION" "$OPENSPEC_TOOLING_TREE"');
    assert.equal(actual[8].run, 'bash tools/openspec-ci/install-runtime.sh');
    assert.equal(gate.shell, 'bash');
    assert.deepEqual(gate.env, { OPENSPEC_PRODUCT_REVISION: revision, OPENSPEC_PRODUCT_TREE: tree,
        OPENSPEC_TOOLING_PRESENT: toolingPresent, OPENSPEC_TOOLING_REVISION: toolingRevision,
        OPENSPEC_TOOLING_TREE: toolingTree });
});

function runGate(t, phase = '', tooling = false, outputs = {}) {
    const temp = fixture(t);
    const rt = path.join(temp, 'openspec-ci');
    const bin = path.join(temp, 'bin');
    const argvLog = path.join(temp, 'trace');
    write(path.join(rt, 'node/bin/node'), [
        '#!/usr/bin/env bash', 'set -eu',
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
        '#!/usr/bin/env bash', 'set -eu',
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
        '    [[ "$2" == --snapshot && "$3" == "$GITHUB_WORKSPACE" ]]',
        '    if [[ "$OPENSPEC_TOOLING_PRESENT" == true ]]; then',
        '      [[ "$#" == 11 && "$8" == --tooling-source-repo && "$9" == "$GITHUB_WORKSPACE/.openspec-tooling-source" ]]',
        '      [[ "${10}" == --tooling-source-revision && "${11}" == "$OPENSPEC_TOOLING_REVISION" ]]',
        '    else [[ "$#" == 7 ]]; fi',
        '    [[ "$4" == --source-repo && "$5" == "$GITHUB_WORKSPACE/.openspec-product-source" ]]',
        '    [[ "$6" == --source-revision && "$7" == "$OPENSPEC_PRODUCT_REVISION" ]]',
        '    phase=reference ;;',
        '  tools/openspec-ci/check-result.py)',
        '    [[ "$2" == "$RUNNER_TEMP/openspec-ci/references.json" ]]',
        '    [[ "$3" == "$OPENSPEC_PRODUCT_REVISION" && "$4" == "$OPENSPEC_PRODUCT_TREE" ]]',
        '    if [[ "$OPENSPEC_TOOLING_PRESENT" == true ]]; then',
        '      [[ "$#" == 6 && "$5" == "$OPENSPEC_TOOLING_REVISION" && "$6" == "$OPENSPEC_TOOLING_TREE" ]]',
        '    else [[ "$#" == 4 ]]; fi',
        '    phase=envelope ;;',
        '  *) exit 98 ;;',
        'esac',
        'echo "$phase" >> "$CI_FIXTURE_LOG"',
        '[[ "$phase" != "$CI_FIXTURE_FAIL" ]] || exit 42',
        'if [[ "$phase" == reference ]]; then echo \'{"referenceIntegrity":true}\'; fi',
        '',
    ].join('\n'));
    const result = invoke('bash', ['-c', gate.run], {
        ...gate.env, OPENSPEC_TOOLING_PRESENT: String(tooling),
        OPENSPEC_TOOLING_REVISION: tooling ? 'a'.repeat(40) : '', OPENSPEC_TOOLING_TREE: tooling ? 'b'.repeat(40) : '',
        PATH: bin + path.delimiter + process.env.PATH, RUNNER_TEMP: temp,
        GITHUB_WORKSPACE: root, CI_FIXTURE_FAIL: phase, CI_FIXTURE_LOG: argvLog, ...outputs,
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
        '#!/usr/bin/env bash', 'set -eu',
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


test('enabled check passes the exact tooling pair and propagates reference and envelope failures', t => {
    for (const phase of ['', 'reference', 'envelope']) {
        const { result, trace } = runGate(t, phase, true);
        assert.equal(result.status, phase ? 42 : 0, result.stderr);
        assert.deepEqual(trace, phase ? phases.slice(0, phases.indexOf(phase) + 1) : phases);
    }
});

test('check body refuses missing or inconsistent tooling preparation outputs', t => {
    for (const [tooling, outputs] of [
        [true, { OPENSPEC_TOOLING_REVISION: '' }],
        [true, { OPENSPEC_TOOLING_TREE: 'not a tree' }],
        [false, { OPENSPEC_TOOLING_REVISION: revision }],
        [false, { OPENSPEC_TOOLING_PRESENT: '' }],
    ]) {
        const { result, trace } = runGate(t, '', tooling, outputs);
        assert.equal(result.status, 1, result.stderr);
        assert.deepEqual(trace, phases.slice(0, 3), 'checker must not receive an unverified tooling pair');
    }
});

test('actual plan body emits only a validated pin, and refuses invalid or symlinked records', t => {
    const ws = fixture(t);
    const output = path.join(ws, 'outputs');
    const shard = path.join(ws, 'openspec/coverage/tooling-authoring.json');
    const record = { schemaVersion: 1, owner: 'tooling', sourceDomain: 'tooling',
        sourceRevision: revision, sourceTree: tree, files: [], requirements: [], sourceAreas: [], knownGaps: [] };
    const env = { GITHUB_WORKSPACE: ws, GITHUB_OUTPUT: output };
    const run = () => {
        fs.rmSync(output, { force: true });
        return invoke('bash', ['-e', '-c', byId('openspec-tooling-plan').run], env);
    };
    assert.equal(run().status, 0);
    assert.equal(fs.readFileSync(output, 'utf8'), 'present=false\n');
    write(shard, JSON.stringify(record));
    assert.equal(run().status, 0);
    assert.equal(fs.readFileSync(output, 'utf8'), `present=true\nrevision=${revision}\ntree=${tree}\n`);
    for (const [data, diagnostic] of [
        [JSON.stringify({ ...record, sourceRevision: 'main\nref=bad' }), 'INVALID_DIGEST'],
        [JSON.stringify({ ...record, schemaVersion: true }), 'SCHEMA_VERSION'],
        ['{"schemaVersion":1,"schemaVersion":1}', 'DUPLICATE_JSON_KEY'],
        [JSON.stringify({ ...record, files: false }), 'ARRAY_REQUIRED'],
    ]) {
        write(shard, data);
        const bad = run();
        assert.equal(bad.status, 1);
        assert.match(bad.stderr, new RegExp(diagnostic));
        assert.equal(fs.existsSync(output), false);
    }
    fs.unlinkSync(shard);
    fs.symlinkSync('missing', shard);
    const unsafe = run();
    assert.equal(unsafe.status, 1);
    assert.match(unsafe.stderr, /SYMLINK_PATH/);
    assert.equal(fs.existsSync(output), false);
});

test('real independent checkouts pass preflight and tooling scripts refuse collisions or wrong inputs', t => {
    const ws = fs.realpathSync(fixture(t));
    const src = path.join(ws, '.openspec-tooling-source');
    const product = path.join(ws, '.openspec-product-source');
    function git(dir, ...args) {
        const result = invoke('git', ['-C', dir, ...args], {
            GIT_CONFIG_GLOBAL: '/dev/null', GIT_CONFIG_NOSYSTEM: '1', GIT_TEMPLATE_DIR: '',
        });
        assert.equal(result.status, 0, result.stderr);
        return result.stdout.trim();
    }
    function initialize(dir, value) {
        write(path.join(dir, 'identity.txt'), value);
        git(dir, 'init', '-q');
        git(dir, 'add', 'identity.txt');
        git(dir, '-c', 'user.name=Fixture', '-c', 'user.email=fixture@example.invalid',
            'commit', '-qm', 'local fixture');
        return [git(dir, 'rev-parse', 'HEAD'), git(dir, 'rev-parse', 'HEAD^{tree}')];
    }
    const [primary] = initialize(ws, 'primary');
    const [productCommit, productTree] = initialize(product, 'product');
    const env = { GITHUB_WORKSPACE: ws, GITHUB_SHA: primary };
    const reserve = () => invoke('bash', ['-e', '-c', byId('openspec-tooling-reserve').run], env);
    assert.equal(reserve().status, 0);
    const verify = (commit, expected, extra = {}) => invoke('bash', ['-e', '-c', byId('openspec-tooling-verify').run], {
        ...env, ...extra, OPENSPEC_TOOLING_REVISION: commit, OPENSPEC_TOOLING_TREE: expected,
    });
    assert.match(verify(revision, tree).stderr, /missing separate tooling Git checkout/);
    fs.symlinkSync('missing', src);
    const collision = reserve();
    assert.equal(collision.status, 1);
    assert.match(collision.stderr, /reserved tooling source directory already exists/);
    fs.unlinkSync(src);
    const [toolCommit, toolTree] = initialize(src, 'tooling');
    const productResult = invoke('bash', ['tools/openspec-ci/check-source.sh', 'verify', productCommit, productTree], env);
    assert.equal(productResult.status, 0, productResult.stderr);
    assert.equal(verify(toolCommit, toolTree).status, 0);
    for (const [commit, expected, extra, message] of [
        [productCommit, toolTree, {}, /tooling checkout HEAD differs/],
        [toolCommit, productTree, {}, /tooling commit tree does not match/],
        [toolCommit, toolTree, { GITHUB_SHA: productCommit }, /primary checkout HEAD differs/],
    ]) {
        const bad = verify(commit, expected, extra);
        assert.equal(bad.status, 1, bad.stderr);
        assert.match(bad.stderr, message);
    }
    assert.equal(git(ws, 'rev-parse', 'HEAD'), primary);
    fs.unlinkSync(path.join(src, '.git/objects', toolCommit.slice(0, 2), toolCommit.slice(2)));
    const missingObject = verify(toolCommit, toolTree);
    assert.equal(missingObject.status, 1);
    assert.match(missingObject.stderr, /required tooling object is not a locally available commit/);
});

test('actual result guard binds both tooling fields and refuses extra fields in legacy mode', t => {
    const out = path.join(fixture(t), 'result.json');
    const legacy = { referenceIntegrity: true, verificationAuthority: 'not-assessed', coverageComplete: false,
        productSourceRevision: revision, productSourceTree: tree };
    const tr = 'a'.repeat(40);
    const tt = 'b'.repeat(40);
    const enabled = { ...legacy, toolingSourceRevision: tr, toolingSourceTree: tt };
    for (const [result, args, expected] of [
        [enabled, [tr, tt], 0], [enabled, [], 1], [legacy, [tr, tt], 1],
        [{ ...enabled, toolingSourceRevision: revision }, [tr, tt], 1],
        [{ ...enabled, toolingSourceTree: tree }, [tr, tt], 1],
    ]) {
        write(out, JSON.stringify(result));
        const run = invoke('python3', ['-BEs', 'tools/openspec-ci/check-result.py', out, revision, tree, ...args]);
        assert.equal(run.status, expected, run.stderr);
        if (expected) assert.match(run.stderr, /required tooling pin/);
    }
});
