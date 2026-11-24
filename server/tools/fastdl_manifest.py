#!/usr/bin/env python3
"""Signed file manifest for FastDL-WON.

  fastdl_manifest.py keygen KEYFILE           create an Ed25519 key (mode 0600), print the public key
  fastdl_manifest.py pubkey KEYFILE           print the public key (value for sv_won_dlkey)
  fastdl_manifest.py build [--prune] WEBROOT KEYFILE TREE
                                              write WEBROOT/fastdl.manifest for the tree (URL) name
                                              TREE = last path segment of sv_won_downloadurl, "-" for none
                                              --prune: delete every file and symlink the manifest does not
                                              list (only for a generated tree of hardlinks/copies)

The manifest lists BLAKE2b-256, size and path of every file the client may fetch and is signed with
the key; the client only downloads files that are listed and match. Path rules and size limits mirror
client/fastdl/core.c (fdl_classify) - files outside them are skipped with a warning, because the
client would reject the whole manifest otherwise.
"""
import hashlib, os, re, sys, tempfile, time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

MB = 1024 * 1024
# (first dir or None for the game dir root, subdirs allowed, extension, size limit)
RULES = [
    (None, False, 'wad', 64 * MB),
    ('maps', False, 'bsp', 64 * MB), ('maps', False, 'res', 256 * 1024), ('maps', False, 'txt', 256 * 1024),
    ('models', True, 'mdl', 32 * MB), ('models', True, 'bmp', 4 * MB),
    ('sound', True, 'wav', 16 * MB), ('sound', True, 'mp3', 32 * MB), ('media', True, 'mp3', 32 * MB),
    ('sprites', True, 'spr', 8 * MB), ('sprites', True, 'txt', 256 * 1024),
    ('gfx', True, 'tga', 16 * MB), ('gfx', True, 'bmp', 16 * MB),
    ('overviews', False, 'bmp', 4 * MB), ('overviews', False, 'tga', 4 * MB), ('overviews', False, 'txt', 256 * 1024),
]
COMP = re.compile(r'[A-Za-z0-9_\-.+!()\[\]]+')      # used with fullmatch: no '$' before a final newline
DEVICES = {'con', 'prn', 'aux', 'nul', 'conin$', 'conout$', 'clock$'} | {f'{p}{d}' for p in ('com', 'lpt') for d in range(10)}


def limit_for(path):
    """size limit if the client would classify path as FDL_FETCH, else None"""
    if len(path) > 200 or path.startswith('!') or '..' in path or ':' in path:
        return None
    comps = path.split('/')
    if len(comps) > 8:
        return None
    for c in comps:
        if not c or not COMP.fullmatch(c) or c[0] == '.' or c[-1] == '.' or c.split('.')[0].lower() in DEVICES:
            return None
    if '.' not in comps[-1]:
        return None
    ext = comps[-1].rsplit('.', 1)[1].lower()
    for d, sub, e, lim in RULES:
        if e != ext:
            continue
        if d is None:
            if len(comps) == 1:
                return lim
        elif len(comps) >= 2 and comps[0].lower() == d and (sub or len(comps) == 2):
            return lim
    return None


def load_key(path):
    if os.stat(path).st_mode & 0o077:
        sys.exit(f'{path} is readable or writable by other users - chmod 600 it (and treat it as leaked if it was exposed)')
    with open(path, 'rb') as f:
        return serialization.load_pem_private_key(f.read(), password=None)


def pubhex(key):
    return key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw).hex()


def keygen(path):
    if os.path.exists(path):
        sys.exit(f'{path} exists - refusing to overwrite a signing key')
    key = Ed25519PrivateKey.generate()
    pem = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    os.makedirs(os.path.dirname(os.path.abspath(path)), mode=0o700, exist_ok=True)
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, 'wb') as f:
        f.write(pem)
    print(pubhex(key))


MAX_ENTRIES, MAX_BYTES = 65536, 8 * 1024 * 1024    # client limits (core.h)
TREE = re.compile(r"(-|[A-Za-z0-9_~-][A-Za-z0-9._~-]{0,31})\Z")     # a URL segment never starts with '.'; \Z: no final newline


def lowfirst(name):
    """walk order: of names that differ only in case, the lowercase one is kept (what servers reference)"""
    return name.lower().encode('utf-8', 'surrogateescape'), name != name.lower(), name


def magic_ok(rel, head, size):
    """the client's fdl_magic_ok: the first bytes must fit the file type (catches a config or a key under an
    allowed name); .txt/.res are checked for NUL bytes while hashing"""
    ext = rel.rsplit('.', 1)[-1].lower()
    le32 = lambda b: int.from_bytes(b[:4], 'little')
    if ext == 'bsp':
        return len(head) >= 4 and le32(head) == 30
    if ext == 'wad':
        return len(head) >= 12 and head[:4] in (b'WAD3', b'WAD2') and le32(head[8:12]) <= size
    if ext == 'mdl':
        return head[:4] in (b'IDST', b'IDSQ')
    if ext == 'spr':
        return head[:4] == b'IDSP'
    if ext == 'wav':
        return len(head) >= 12 and head[:4] == b'RIFF' and head[8:12] == b'WAVE'
    if ext == 'bmp':
        return head[:2] == b'BM'
    if ext == 'tga':
        return len(head) >= 3 and head[1] <= 1 and head[2] in (1, 2, 3, 9, 10, 11)
    if ext == 'mp3':
        return head[:3] == b'ID3' or (len(head) >= 2 and head[0] == 0xFF and (head[1] & 0xE0) == 0xE0)
    return ext in ('txt', 'res')


def build(root, keyfile, tree, prune=False, serial=None):
    if not TREE.match(tree):
        sys.exit(f"bad tree name {tree!r}")
    key = load_key(keyfile)
    entries, skipped, seen, drop = [], [], {}, []
    for dirpath, dirs, files in os.walk(root):
        dirs.sort(key=lowfirst)
        for d in dirs:
            if os.path.islink(os.path.join(dirpath, d)):
                skipped.append((os.path.relpath(os.path.join(dirpath, d), root).replace(os.sep, '/'), 'symlinked directory'))
                drop.append(os.path.join(dirpath, d))
        for name in sorted(files, key=lowfirst):
            full = os.path.join(dirpath, name)
            rel = os.path.relpath(full, root).replace(os.sep, '/')
            if rel == 'fastdl.manifest':
                continue
            if not os.path.isfile(full) or os.path.islink(full):
                skipped.append((rel, 'not a regular file'))
                drop.append(full)
                continue
            if any(ord(ch) < 0x20 or ord(ch) == 0x7f for ch in rel):
                skipped.append((rel.encode('unicode_escape').decode(), 'control character in the name'))
                drop.append(full)
                continue
            st = os.stat(full)
            if not st.st_mode & 0o044:
                skipped.append((rel, 'not readable by the web server (needs read permission for group or others)'))
                drop.append(full)
                continue
            lim = limit_for(rel)
            size = os.path.getsize(full)
            if lim is None or size == 0 or size > lim:
                skipped.append((rel, 'type/path not allowed' if lim is None else f'size {size} (limit {lim})'))
                drop.append(full)
                continue
            low = rel.lower()
            if low in seen:
                skipped.append((rel, f'differs only in case from {seen[low]}'))
                drop.append(full)
                continue
            h = hashlib.blake2b(digest_size=32)
            n, head, nul = 0, b'', False
            text = rel.lower().endswith(('.txt', '.res'))
            with open(full, 'rb') as f:
                for chunk in iter(lambda: f.read(1 << 20), b''):
                    h.update(chunk)
                    if not head:
                        head = chunk[:16]
                    nul = nul or (text and b'\0' in chunk)
                    n += len(chunk)
            if n != size:
                sys.exit(f'{rel} changed while building the manifest - run again')
            if nul or not magic_ok(rel, head, size):
                skipped.append((rel, 'content does not match the file type'))
                drop.append(full)
                continue
            seen[low] = rel
            entries.append((low, h.hexdigest(), size, rel))
    entries.sort(key=lambda e: e[0].encode())       # same order as the client's fdl_path_cmp
    if len(entries) > MAX_ENTRIES:
        sys.exit(f'{len(entries)} files - clients accept at most {MAX_ENTRIES}')
    # serial: increases with every build (time, at least previous + 1); clients refuse a lower one (replay)
    if serial is None:
        serial = int(time.time())
        try:
            serial = max(serial, int(os.environ.get('FASTDL_PREV_SERIAL', '0')) + 1)
        except ValueError:
            pass
    body = b'FASTDL-WON1\n' + f'tree {tree} {serial}\n'.encode() + b''.join(f'{h} {s} {p}\n'.encode() for _, h, s, p in entries)
    data = body + b'sig ' + key.sign(body).hex().encode() + b'\n'
    if len(data) >= MAX_BYTES:
        sys.exit(f'manifest is {len(data)} bytes - clients accept less than {MAX_BYTES}')
    fd, tmp = tempfile.mkstemp(dir=root, prefix='.fastdl.manifest.')
    with os.fdopen(fd, 'wb') as f:
        f.write(data)
    os.chmod(tmp, 0o644)
    os.replace(tmp, os.path.join(root, 'fastdl.manifest'))
    if prune:
        for p in drop:
            os.unlink(p)
        for dirpath, dirs, files in os.walk(root, topdown=False):
            if dirpath != root and not os.listdir(dirpath):
                os.rmdir(dirpath)
    for rel, why in skipped:
        print(f'  skipped {rel}: {why}', file=sys.stderr)
    print(f'{root}/fastdl.manifest: {len(entries)} files, {len(data)} bytes, {len(skipped)} skipped; key {pubhex(key)}')


if __name__ == '__main__':
    if len(sys.argv) == 3 and sys.argv[1] == 'keygen':
        keygen(sys.argv[2])
    elif len(sys.argv) == 3 and sys.argv[1] == 'pubkey':
        print(pubhex(load_key(sys.argv[2])))
    elif len(sys.argv) == 5 and sys.argv[1] == 'build':
        build(sys.argv[2], sys.argv[3], sys.argv[4])
    elif len(sys.argv) == 6 and sys.argv[1] == 'build' and sys.argv[2] == '--prune':
        build(sys.argv[3], sys.argv[4], sys.argv[5], prune=True)
    else:
        sys.exit(__doc__)
