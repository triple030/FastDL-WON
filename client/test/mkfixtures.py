#!/usr/bin/env python3
"""Fixtures for test_core: a signed manifest, validly signed but malformed manifests, and a
classification list (Python rules) for every file in build/dl (optional) plus adversarial names."""
import os, sys, hashlib
sys.path.insert(0, os.path.join(os.path.dirname(__file__), '../../server/tools'))
import fastdl_manifest as fm
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives import serialization

out = sys.argv[1]; os.makedirs(out, exist_ok=True)
root = os.path.join(out, 'web'); os.makedirs(root, exist_ok=True)
files = {'maps/test.bsp': b'\x1e\0\0\0' + b'x' * 100, 'maps/test.txt': b'hello', 'cs_test.wad': b'WAD3' + b'\0' * 20,
         'sound/a/b.wav': b'RIFF\0\0\0\0WAVEfmt ', 'models/player/p/p.mdl': b'IDST' + b'\0' * 8,
         'sprites/s.spr': b'IDSP\0\0', 'gfx/env/skyup.tga': b'\0\0\x02' + b'\0' * 15,
         'maps/skip.cfg': b'rcon_password x', 'readme.md': b'no'}
for p, d in files.items():
    os.makedirs(os.path.dirname(os.path.join(root, p)) or root, exist_ok=True)
    open(os.path.join(root, p), 'wb').write(d)
keyfile = os.path.join(out, 'test.key')
if os.path.exists(keyfile): os.remove(keyfile)
fm.keygen(keyfile)
fm.build(root, keyfile, 'web')
key = fm.load_key(keyfile)
other = Ed25519PrivateKey.generate()
open(os.path.join(out, 'pub'), 'w').write(fm.pubhex(key))
open(os.path.join(out, 'otherpub'), 'w').write(fm.pubhex(other))

def signed(name, body):
    open(os.path.join(out, 'bad_' + name), 'wb').write(body + b'sig ' + key.sign(body).hex().encode() + b'\n')
H = hashlib.blake2b(b'x', digest_size=32).hexdigest()
signed('unsorted', f'FASTDL-WON1\ntree web\n{H} 1 maps/b.bsp\n{H} 1 maps/a.bsp\n'.encode())
signed('dup_case', f'FASTDL-WON1\ntree web\n{H} 1 maps/a.bsp\n{H} 1 maps/A.bsp\n'.encode())
signed('cfg', f'FASTDL-WON1\ntree web\n{H} 1 autoexec.cfg\n'.encode())
signed('traversal', f'FASTDL-WON1\ntree web\n{H} 1 maps/../../x.bsp\n'.encode())
signed('backslash', f'FASTDL-WON1\ntree web\n{H} 1 maps\\a.bsp\n'.encode())
signed('too_big', f'FASTDL-WON1\ntree web\n{H} 67108865 maps/a.bsp\n'.encode())
signed('size_zero', f'FASTDL-WON1\ntree web\n{H} 0 maps/a.bsp\n'.encode())
signed('size_lead0', f'FASTDL-WON1\ntree web\n{H} 01 maps/a.bsp\n'.encode())
signed('size_overflow', f'FASTDL-WON1\ntree web\n{H} 99999999999 maps/a.bsp\n'.encode())
signed('crlf', f'FASTDL-WON1\r\ntree web\r\n{H} 1 maps/a.bsp\r\n'.encode())
signed('short_hash', f'FASTDL-WON1\ntree web\n{H[:62]} 1 maps/a.bsp\n'.encode())
signed('nonhex_hash', f'FASTDL-WON1\ntree web\n{"g" * 64} 1 maps/a.bsp\n'.encode())
signed('two_spaces', f'FASTDL-WON1\ntree web\n{H}  1 maps/a.bsp\n'.encode())
signed('empty_line', f'FASTDL-WON1\ntree web\n\n{H} 1 maps/a.bsp\n'.encode())
signed('nul', f'FASTDL-WON1\ntree web\n{H} 1 maps/a\0.bsp\n'.encode())
signed('no_path', f'FASTDL-WON1\ntree web\n{H} 1 \n'.encode())
signed('wrong_magic', f'WONFASTDL1\ntree web\n{H} 1 maps/a.bsp\n'.encode())	# format id of 3.0 and older
body = f'FASTDL-WON1\ntree web\n{H} 1 maps/a.bsp\n'.encode()
signed('other_tree', f'FASTDL-WON1\ntree hldm\n{H} 1 maps/a.bsp\n'.encode())
signed('no_tree', f'FASTDL-WON1\n{H} 1 maps/a.bsp\n'.encode())
open(os.path.join(out, 'bad_sig_other_body'), 'wb').write(body + b'sig ' + key.sign(body + b'x').hex().encode() + b'\n')
open(os.path.join(out, 'bad_sig_upper'), 'wb').write(body + b'SIG ' + key.sign(body).hex().encode() + b'\n')
open(os.path.join(out, 'bad_sig_short'), 'wb').write(body + b'sig ' + key.sign(body).hex()[:-2].encode() + b'\n')
open(os.path.join(out, 'bad_trailing'), 'wb').write(body + b'sig ' + key.sign(body).hex().encode() + b'\nX')

paths = set()
dl = os.path.join(os.path.dirname(__file__), 'build/dl')
for d, _, fs in os.walk(dl):
    for f in fs:
        rel = os.path.relpath(os.path.join(d, f), dl).replace(os.sep, '/')
        paths.add(rel.split('/', 1)[1] if '/' in rel else rel)
paths |= {'maps/con.bsp', 'maps/a b.bsp', 'maps/LONGNA~1.BSP', 'autoexec.cfg', 'maps/sub/x.bsp', 'MAPS/X.BSP',
          'Sound/A.WAV', 'sound/a(1)[2]+!.wav', 'models/x.wav', 'x.bsp', 'cl_dlls/client.dll', '!MD5aa',
          'sound/a/b/c/d/e/f/g.wav', 'a/b/c/d/e/f/g/h/i.wav', 'overviews/x/y.bmp', 'gfx/x.tga', 'maps/.x.bsp'}
# review 1: seeded random names from the pieces the rules care about (C and Python must agree on each)
import random
rnd = random.Random(1)
parts = ['maps', 'sound', 'models', 'sprites', 'gfx', 'overviews', 'media', 'cl_dlls', 'dlls', 'addons', 'con', 'COM1',
         'lpt0', 'a', 'B', 'x.y', '.', '..', '...', '~1', 'a b', 'a.', '.a', 'aux.x', 'nul', 'conin$', 'CON ', '!MD5',
         'a+b', '(x)', '[y]', 'a-b_c', 'x%41', 'x;y', 'MAPS', 'Sound']
exts = ['bsp', 'wad', 'wav', 'mp3', 'mdl', 'spr', 'tga', 'bmp', 'txt', 'res', 'cfg', 'dll', 'asi', 'gam', 'BSP', 'Wav', 'sc', '']
for _ in range(20000):
    comps = [rnd.choice(parts) for _ in range(rnd.randint(0, 8))]
    last = rnd.choice(parts) + ('.' + rnd.choice(exts) if rnd.random() < 0.9 else '')
    if rnd.random() < 0.1: last += rnd.choice(['.', ' ', '. ', '::$DATA', ':x'])
    p = '/'.join(comps + [last]).replace('//', '/')
    if rnd.random() < 0.05: p = rnd.choice(['/', 'C:', './', '//']) + p
    if rnd.random() < 0.03: p = 'maps/' + 'a' * rnd.randint(185, 200) + '.bsp'
    paths.add(p)
with open(os.path.join(out, 'classify.list'), 'w', encoding='latin-1') as f:
    for p in sorted(paths):
        if '\n' in p or '\t' in p: continue
        f.write(f'{fm.limit_for(p) or 0}\t{p}\n')
print(f'fixtures in {out}: {len(paths)} classify paths')
