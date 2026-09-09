"""Export tracked regular blobs, never execute or follow PR-controlled files."""
import subprocess
from pathlib import Path
from reports import safe_path


def git(source, *args):
    return subprocess.check_output(['git', '-C', str(source), *args])


def snapshot(source, dest):
    dest = Path(dest)
    dest.mkdir(parents=True, exist_ok=True)
    skipped = 0
    total = 0
    count = 0
    # Read Git objects directly: archive would honor PR-controlled export-ignore attributes.
    entries = git(source, 'ls-tree', '-rlz', 'HEAD').split(b'\0')
    proc = subprocess.Popen(['git', '-C', str(source), 'cat-file', '--batch'],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                            stderr=subprocess.DEVNULL)
    submodules = 0
    try:
        for entry in entries:
            if not entry:
                continue
            meta, raw_name = entry.split(b'\t', 1)
            mode, kind, oid, size = meta.split()
            name = safe_path(raw_name.decode())
            if mode == b'160000':
                submodules += 1
                continue
            if mode not in (b'100644', b'100755') or Path(name).name == '.semgrepignore':
                skipped += 1
                continue
            size = int(size)
            total += size
            count += 1
            if size > 5 * 1024 * 1024 or total > 200 * 1024 * 1024 or count > 20000:
                raise ValueError('snapshot exceeds bounded scan size; review manually')
            proc.stdin.write(oid + b'\n')
            proc.stdin.flush()
            header = proc.stdout.readline().split()
            if header != [oid, b'blob', str(size).encode()]:
                raise ValueError('unexpected Git object')
            data = proc.stdout.read(size)
            if len(data) != size or proc.stdout.read(1) != b'\n':
                raise ValueError('truncated Git object')
            target = dest / name
            target.parent.mkdir(parents=True, exist_ok=True)
            target.write_bytes(data)
            target.chmod(0o444)
    finally:
        proc.stdin.close()
        proc.stdout.close()
        rc = proc.wait()
    if rc != 0:
        raise ValueError('Git object export failed')
    return dict(files=count, excluded_symlinks_or_ignore_files=skipped, excluded_submodules=submodules)


def changed_files(source, base, dest):
    merge_base = git(source, 'merge-base', base, 'HEAD').decode().strip()
    changed = git(source, 'diff', '--name-only', '-z', '--diff-filter=ACMRT', merge_base, 'HEAD').split(b'\0')
    names = [safe_path(n.decode()) for n in changed if n]
    # --files-from is newline-delimited; safe_path rejects embedded controls.
    return [n for n in names if (Path(dest) / n).is_file()]
