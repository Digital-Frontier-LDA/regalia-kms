"""Authenticate dated Debian package indexes without disabling Release expiry."""
import argparse
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
import hashlib
import json
import io
import lzma
from pathlib import Path
import re
import shutil
import subprocess
import tempfile

from .fetch_debian import download
from .verify import read_regular, require, VerificationError, run

POLICY = Path(__file__).with_name('package-snapshot-policy.json')
ARCHIVES = {
    'debian': ('trixie', 'archive-key-13.asc', '04B54C3CDCA79751B16BC6B5225629DF75B188BD'),
    'debian-security': ('trixie-security', 'archive-key-13-security.asc', '5E04A1E3223A19A20706E20F9904613D4CCE68C6'),
    'debian-backports': ('trixie-backports', 'archive-key-13.asc', '04B54C3CDCA79751B16BC6B5225629DF75B188BD')}


def archive_url(archive, timestamp):
    # Backports is a suite in the Debian archive, not a separate snapshot archive.
    require(archive in ARCHIVES, 'unapproved snapshot archive')
    upstream = 'debian' if archive == 'debian-backports' else archive
    return f'https://snapshot.debian.org/archive/{upstream}/{timestamp}/'


def policy(data, now=None):
    now = now or datetime.now(timezone.utc)
    require(set(data) == {'schema','timestamp','architecture','max_snapshot_age_days','archives'}, 'invalid snapshot policy fields')
    require(data['schema'] == 'regalia.debian-package-snapshot/v1' and data['architecture'] == 'amd64'
            and type(data['max_snapshot_age_days']) is int and 1 <= data['max_snapshot_age_days'] <= 7,
            'unsupported snapshot policy')
    require(isinstance(data['timestamp'], str) and re.fullmatch(r'\d{8}T\d{6}Z', data['timestamp']), 'invalid snapshot timestamp')
    date = datetime.strptime(data['timestamp'], '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
    require(timedelta(0) <= now-date <= timedelta(days=data['max_snapshot_age_days']), 'snapshot timestamp is future or stale; review a new policy')
    require({'debian', 'debian-security'} <= set(data['archives']) <= set(ARCHIVES),
            'Debian and security snapshots are required; only trixie backports is optional')
    for archive in data['archives']:
        suite, key, fingerprint = ARCHIVES[archive]
        require(data['archives'][archive] == {'suite':suite,'key_file':key,'primary_fingerprint':fingerprint}, 'unapproved archive authority')
    return data


def fields(text):
    result = {}
    for line in text.splitlines():
        if line.startswith(' '):
            require(bool(result), 'orphan continuation')
            result[name] += '\n' + line[1:]
        elif line:
            require(':' in line, 'malformed Debian metadata')
            name, value = line.split(':', 1)
            require(name not in result, 'duplicate Debian metadata field')
            result[name] = value.strip()
    return result


def verify_release(inrelease, key, fingerprint, suite, now=None):
    now = now or datetime.now(timezone.utc)
    signed, public = read_regular(inrelease), read_regular(key)
    with tempfile.TemporaryDirectory(prefix='regalia-snapshot-gpg-') as temp:
        home = Path(temp)
        (home/'key').write_bytes(public); (home/'InRelease').write_bytes(signed)
        gpg=['gpg','--no-options','--homedir',str(home),'--batch','--no-autostart',
             '--no-auto-key-retrieve','--auto-key-locate','clear']
        run(gpg+['--import',str(home/'key')])
        listing = run(gpg+['--with-colons','--fingerprint','--list-keys'])
        primary=[]; current=False
        for line in listing.splitlines():
            record=line.split(':')
            if record[0] in ('pub','sub'): current=record[0]=='pub'
            elif record[0]=='fpr' and current: primary.append(record[9]); current=False
        require(primary==[fingerprint], 'archive key fingerprint mismatch')
        if '--proc-all-sigs' in run(gpg+['--dump-options']).splitlines():
            gpg += ['--proc-all-sigs']
        result=subprocess.run(gpg+['--status-fd','1','--output',str(home/'Release'),
                                  '--decrypt',str(home/'InRelease')],capture_output=True,text=True,timeout=30)
        records=[line.split()[1:] for line in result.stdout.splitlines() if line.startswith('[GNUPG:] ')]
        # Debian can co-sign an InRelease with other release keys. Missing those
        # optional keys does not replace the required pinned primary signature.
        require(result.returncode in (0,2) and not any(r[0] in {'BADSIG','EXPSIG','EXPKEYSIG','REVKEYSIG'} for r in records),
                'bad or expired archive signature')
        require(not any(r[0]=='FAILURE' and r[1:] != ['gpg-exit','33554433'] for r in records),
                'archive verification operation failed')
        valid=[r for r in records if r[0]=='VALIDSIG' and len(r) in (10,11)
               and (r[10] if len(r)==11 else r[1])==fingerprint and r[8] in {'8','9','10'}]
        require(len(valid)==1, 'required pinned archive signature absent')
        release=(home/'Release').read_text(encoding='ascii')
    metadata=fields(release)
    origin = 'Debian Backports' if suite == 'trixie-backports' else 'Debian'
    require(metadata.get('Origin')==origin and metadata.get('Codename')==suite, 'unexpected Release identity')
    date=parsedate_to_datetime(metadata['Date'])
    require(date.tzinfo is not None and date <= now+timedelta(minutes=5), 'future Release date')
    expiry=metadata.get('Valid-Until')
    if suite.endswith(('-security', '-backports')):
        require(expiry is not None, 'security/backports Release expiry missing')
    if expiry:
        expires=parsedate_to_datetime(expiry)
        require(expires.tzinfo is not None and now < expires and date < expires, 'Release expired or invalid')
    sums={}
    for line in metadata['SHA256'].splitlines():
        if not line: continue
        digest, size, name=line.split()
        require(re.fullmatch('[a-f0-9]{64}',digest) and size.isdecimal() and name not in sums,
                'invalid Release SHA256 entry')
        sums[name]=(digest,int(size))
    return {'inrelease_sha256':hashlib.sha256(signed).hexdigest(),'primary_fingerprint':fingerprint,
            'date':date.isoformat(),'valid_until':expiry,'suite':suite}, sums


def packages(data):
    result=[]
    for block in data.decode('utf-8').strip().split('\n\n'):
        item=fields(block)
        required={'Package','Version','Architecture','Filename','SHA256','Size'}
        require(required <= set(item), 'package index lacks authenticated fields')
        require(re.fullmatch('[a-f0-9]{64}',item['SHA256']) and item['Size'].isdecimal()
                and re.fullmatch(r'pool/[A-Za-z0-9/._+~%-]+\.deb',item['Filename'])
                and '..' not in item['Filename'].split('/'), 'unsafe package index entry')
        result.append({key:item[key] for key in sorted(required)})
    return result


def validate(directory, policy_path=POLICY):
    policy_data=read_regular(policy_path)
    config=policy(json.loads(policy_data))
    report={'schema':'regalia.authenticated-package-snapshot/v1','status':'verified',
            'production_approved':False,'timestamp':config['timestamp'],
            'policy_sha256':hashlib.sha256(policy_data).hexdigest(),'archives':{}}
    inventory=[]
    for archive, entry in config['archives'].items():
        root=directory/archive
        verified,sums=verify_release(root/'InRelease',root/entry['key_file'],entry['primary_fingerprint'],entry['suite'])
        name='main/binary-amd64/Packages.xz'
        require(name in sums, 'approved package index absent')
        compressed=read_regular(root/'Packages.xz',32*1024*1024)
        require((hashlib.sha256(compressed).hexdigest(),len(compressed)) == sums[name], 'package index hash or length mismatch')
        with lzma.LZMAFile(io.BytesIO(compressed)) as handle: data=handle.read(128*1024*1024+1)
        require(len(data)<=128*1024*1024, 'package index expansion exceeds bounds')
        items=packages(data)
        verified.update(index_sha256=sums[name][0],packages=len(items),
                        url=archive_url(archive, config['timestamp']))
        report['archives'][archive]=verified
        inventory.extend(dict(item,archive=archive) for item in items)
    return report,inventory


def fetch(destination, policy_path=POLICY):
    policy_data=read_regular(policy_path)
    config=policy(json.loads(policy_data))
    require(not destination.exists(), 'snapshot output already exists')
    destination.parent.mkdir(parents=True,exist_ok=True)
    staging=Path(tempfile.mkdtemp(prefix='.snapshot-',dir=destination.parent))
    try:
        (staging/'policy.json').write_bytes(policy_data)
        for archive, entry in config['archives'].items():
            root=staging/archive;root.mkdir()
            base=archive_url(archive, config['timestamp'])+f'dists/{entry["suite"]}/'
            download('https://ftp-master.debian.org/keys/'+entry['key_file'],root/entry['key_file'],1024*1024)
            download(base+'InRelease',root/'InRelease',4*1024*1024)
            _,sums=verify_release(root/'InRelease',root/entry['key_file'],entry['primary_fingerprint'],entry['suite'])
            require('main/binary-amd64/Packages.xz' in sums, 'package index absent')
            download(base+'main/binary-amd64/Packages.xz',root/'Packages.xz',32*1024*1024)
        report,inventory=validate(staging,staging/'policy.json')
        (staging/'verification.json').write_text(json.dumps(report,indent=2)+'\n')
        (staging/'package-index.json').write_text(json.dumps(inventory,indent=2)+'\n')
        require(not destination.exists(), 'snapshot output appeared during capture')
        staging.rename(destination)
        return report
    finally:
        if staging.exists(): shutil.rmtree(staging)


def check_installed(path, inventory):
    allowed={(x['Package'],x['Version']) for x in inventory}
    rows=[line.split('\t') for line in path.read_text().splitlines()]
    require(bool(rows) and all(len(row)==2 for row in rows), 'invalid installed package inventory')
    require(all((name.split(':',1)[0],version) in allowed for name,version in rows),
            'installed package version absent from authenticated snapshot indexes')
    return {'status':'verified','packages':len(rows),'inventory_sha256':hashlib.sha256(path.read_bytes()).hexdigest()}


def render_preseed(text, config):
    config=policy(config)
    require(text.count('d-i mirror/http/hostname string deb.debian.org')==1
            and text.count('d-i mirror/http/directory string /debian')==1, 'unexpected mirror template')
    text=text.replace('d-i mirror/http/hostname string deb.debian.org','d-i mirror/http/hostname string snapshot.debian.org')
    text=text.replace('d-i mirror/http/directory string /debian',f'd-i mirror/http/directory string /archive/debian/{config["timestamp"]}')
    result = text + '\n# Fixed snapshot security repository; keep normal APT signature/expiry checks.\n' + \
        'd-i apt-setup/services-select multiselect\n' + \
        f'd-i apt-setup/local0/repository string http://snapshot.debian.org/archive/debian-security/{config["timestamp"]}/ trixie-security main\n' + \
        'd-i apt-setup/local0/comment string authenticated dated Debian security snapshot\n' + \
        'd-i apt-setup/local0/source boolean false\n'
    if 'debian-backports' in config['archives']:
        result += f'd-i apt-setup/local1/repository string http://snapshot.debian.org/archive/debian/{config["timestamp"]}/ trixie-backports main\n' + \
            'd-i apt-setup/local1/comment string authenticated dated Debian backports snapshot\n' + \
            'd-i apt-setup/local1/source boolean false\n'
    return result


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('destination',type=Path)
    parser.add_argument('--policy',type=Path,default=POLICY)
    args=parser.parse_args()
    try: print(json.dumps(fetch(args.destination,args.policy),indent=2))
    except (VerificationError,ValueError,OSError,subprocess.SubprocessError) as error: parser.exit(1,f'REFUSED: {error}\n')

if __name__=='__main__': main()
