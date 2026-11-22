const fs = require('node:fs');

function check(condition, message) {
    if (!condition) throw new Error(message);
}

const [manifestPath, lockPath] = process.argv.slice(2);
const manifest = JSON.parse(fs.readFileSync(manifestPath, 'utf8'));
const lock = JSON.parse(fs.readFileSync(lockPath, 'utf8'));
const pins = {
    '@fission-ai/openspec': {
        version: '2.1.1',
        resolved: 'https://registry.npmjs.org/@fission-ai/openspec/-/openspec-2.1.1.tgz',
        integrity: 'sha512-GQv1xU4uLrTVJ6MfOKNIxo/BgEk+e8C/XBmjTfzd/W3LNh4v2UMAsfTdn8mjHdjDA/KjfGstwUhZedQW4hdcZQ==',
    },
    yaml: {
        version: '2.9.1',
        resolved: 'https://registry.npmjs.org/yaml/-/yaml-2.9.1.tgz',
        integrity: 'sha512-3NxN8+78OdzbT7C/WjGsyfPAtJaN3FNDsWxv7Y7mcDsT/oOmgW8BpyQQFFBnvZE3j9Y2Sdz1ULFLezL7Eb2yFw==',
    },
};
check(lock.lockfileVersion === 3 && lock.packages?.[''], 'expected a v3 npm lock with a root package');
for (const deps of [manifest.dependencies, lock.packages[''].dependencies]) {
    check(Object.keys(deps).length === Object.keys(pins).length, 'unexpected direct npm dependency');
    for (const [name, pin] of Object.entries(pins)) {
        check(deps[name] === pin.version, 'unlocked direct dependency: ' + name);
        const stored = lock.packages['node_modules/' + name];
        for (const [field, expected] of Object.entries(pin)) {
            check(stored?.[field] === expected, 'npm pin mismatch: ' + name + ' ' + field);
        }
    }
}
for (const [name, entry] of Object.entries(lock.packages)) {
    if (name === '') continue;
    check(name.startsWith('node_modules/') && !entry.link, 'unexpected package entry: ' + name);
    const url = new URL(entry.resolved);
    check(url.origin === 'https://registry.npmjs.org' && !url.username && !url.password &&
          !url.search && !url.hash && url.pathname.endsWith('.tgz'), 'unapproved npm tarball: ' + name);
    check(/^sha512-[A-Za-z0-9+/]{86}==$/.test(entry.integrity), 'missing npm integrity: ' + name);
}
