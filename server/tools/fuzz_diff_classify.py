#!/usr/bin/env python3
"""Review 2: differential fuzzing of the builder's path rules (fastdl_manifest.limit_for) against the client's
(core.c fdl_classify). Any path the builder would list must be FDL_FETCH with the same limit in the client,
otherwise every client rejects the whole manifest ("malformed entry").
usage: python3 -I tools/fuzz_diff_classify.py SECONDS   (needs docker for the gcc:13 build of the helper)"""
import os, random, subprocess, sys, tempfile, time

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fastdl_manifest as fm  # noqa: E402

CLIENT = os.path.join(os.path.dirname(os.path.dirname(HERE)), 'client')
secs = float(sys.argv[1]) if len(sys.argv) > 1 else 60
out = tempfile.mkdtemp(prefix='fdl-diff-')
subprocess.run(['docker', 'run', '--rm', '-v', f'{CLIENT}:/src:ro', '-v', f'{out}:/o', 'gcc:13', 'bash', '-c',
                f'gcc -std=c99 -O2 -static -o /o/dc /src/test/diff_classify.c /src/core.c /src/third_party/monocypher/monocypher.c /src/third_party/monocypher/monocypher-ed25519.c && chown {os.getuid()}:{os.getgid()} /o/dc'],
               check=True)
helper = os.path.join(out, 'dc')

parts = ['maps', 'MAPS', 'sound', 'models', 'sprites', 'gfx', 'overviews', 'media', 'cl_dlls', 'dlls', 'addons', 'con',
         'COM1', 'lpt9', 'nul', 'clock$', 'a', 'B', 'x.y', '.', '..', '~1', 'a b', 'a.', '.a', 'aux.x', '!MD5', 'a+b',
         '(x)', '[y]', 'a-b_c', 'ä', 'x%41']
exts = ['bsp', 'wad', 'wav', 'mp3', 'mdl', 'spr', 'tga', 'bmp', 'txt', 'res', 'cfg', 'dll', 'BSP', 'Wav', 'sc', '']
noise = ['\n', '\r', '\t', ' ', '.', '/', '\\', ':', '\0', '\x7f', '\xff', 'ä', 'K', 'İ', '~', '$', '%']


def gen(r):
    comps = [r.choice(parts) for _ in range(r.randint(0, 9))]
    last = r.choice(parts) + ('.' + r.choice(exts) if r.random() < 0.9 else '')
    s = '/'.join(comps + [last])
    for _ in range(r.randint(0, 3)):
        i = r.randint(0, len(s))
        s = s[:i] + r.choice(noise) + s[i:]
    if r.random() < 0.05:
        s = 'sound/' + 'a' * r.randint(180, 200) + '.wav'
    return s.replace('\0', '')


r = random.Random(int(os.environ.get('SEED', '2')))
t0, total, bad, shown = time.time(), 0, 0, set()
while time.time() - t0 < secs:
    batch = [gen(r) for _ in range(20000)]
    raw = [p.encode('utf-8', 'surrogateescape') for p in batch]
    res = subprocess.run([helper], input=b'\0'.join(raw) + b'\0', capture_output=True, check=True).stdout.split(b'\n')
    for p, line in zip(batch, res):
        total += 1
        py = fm.limit_for(p)
        k, lim = map(int, line.split())
        if py is not None and (k != 1 or lim != py):
            bad += 1
            key = repr(p)[:80]
            if len(shown) < 15 and key not in shown:
                shown.add(key)
                print(f'MISMATCH builder lists {p!r} (limit {py}) but client says class {k} limit {lim}')
print(f'diff_classify: {total} paths, {bad} builder-accepts/client-rejects mismatches')
sys.exit(1 if bad else 0)
