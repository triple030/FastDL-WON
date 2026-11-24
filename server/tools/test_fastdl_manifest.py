#!/usr/bin/env python3
"""Tests for the server tools (review 1): fastdl_manifest.py rules and build, mkfastdl.sh against a hostile
mod folder, static checks of the compose and nginx files.  usage: python3 -I tools/test_fastdl_manifest.py
Tests named test_gap_* describe a rule the tools do not enforce yet (REVIEW.md) and fail until it is fixed."""
import hashlib, os, stat, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
SERVER = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import fastdl_manifest as fm  # noqa: E402
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey  # noqa: E402


def write(path, data=b'x', mode=None):
    os.makedirs(os.path.dirname(path) or '.', exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)
    if mode is not None:
        os.chmod(path, mode)


def parse(manifest_path, key):
    """verify like the client and return [(hash, size, path)]"""
    data = open(manifest_path, 'rb').read()
    body, sigline = data[:-133], data[-133:]
    assert sigline.startswith(b'sig ') and sigline.endswith(b'\n')
    Ed25519PublicKey.from_public_bytes(bytes.fromhex(fm.pubhex(key))).verify(bytes.fromhex(sigline[4:132].decode()), body)
    lines = body.decode().split('\n')
    assert lines[0] == 'FASTDL-WON1' and lines[1].startswith('tree ') and lines[-1] == ''
    return [(h, int(s), p) for h, s, p in (ln.split(' ', 2) for ln in lines[2:-1])]


BSP = b'\x1e\0\0\0' + b'm' * 60


class Rules(unittest.TestCase):
    def test_limit_for_refuses(self):
        for p in ['autoexec.cfg', 'maps/x.cfg', 'liblist.gam', 'cl_dlls/client.dll', 'dlls/mp.dll', 'fastdl.asi',
                  'addons/x.wav', 'maps/../x.bsp', '../x.wad', '/x.wad', 'C:x.wad', 'maps/x.bsp:ads', 'maps/con.bsp',
                  'maps/COM1.bsp', 'maps/lpt0.x.bsp', 'aux/x.wav', 'maps/a b.bsp', 'maps/LONGNA~1.BSP', 'maps/.x.bsp',
                  'maps/x.bsp.', 'maps/x.bsp ', 'maps//x.bsp', 'maps/sub/x.bsp', 'x.bsp', 'models/x.wav', 'sound/x.txt',
                  'maps/x', '', '!MD5' + '0' * 32, 'maps/ä.bsp', 'maps/x\\y.bsp', 'maps/x\n.bsp', 'maps/x%41.bsp',
                  'a/b/c/d/e/f/g/h/i.wav', 'maps/' + 'a' * 192 + '.bsp', 'fastdl.manifest', 'maps/x.key', 'keys/fastdl.key']:
            self.assertIsNone(fm.limit_for(p), p)

    def test_limit_for_allows(self):
        for p, lim in [('maps/de_dust.bsp', 64 << 20), ('MAPS/DE_DUST.BSP', 64 << 20), ('x.wad', 64 << 20),
                       ('maps/x.txt', 256 << 10), ('sound/a/b/c/d/e/f/g.wav', 16 << 20), ('models/p/a/a.bmp', 4 << 20),
                       ('gfx/env/a.tga', 16 << 20), ('overviews/a.txt', 256 << 10), ('maps/' + 'a' * 191 + '.bsp', 64 << 20)]:
            self.assertEqual(fm.limit_for(p), lim, p)

    def test_gap_tree_name_newline(self):
        # TREE uses re.match with '$', which also matches before a final newline: "a\n" is accepted and the
        # manifest gets an empty line after the tree line (every client rejects it)
        self.assertIsNone(fm.TREE.match('a\n'))

    def test_tree_names(self):
        for t in ['', '.x', 'a/b', 'a b', 'a' * 33, '..', '-x/']:
            self.assertIsNone(fm.TREE.match(t), repr(t))
        for t in ['-', 'cstrike', 'cs_1.5', 'a~b', 'a' * 32]:
            self.assertIsNotNone(fm.TREE.match(t), t)


class Build(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.key = os.path.join(self.d, 'keys', 'fastdl.key')
        with open(os.devnull, 'w') as null:
            old, sys.stdout = sys.stdout, null
            try:
                fm.keygen(self.key)
            finally:
                sys.stdout = old
        self.k = fm.load_key(self.key)
        self.root = os.path.join(self.d, 'tree')
        os.makedirs(self.root)

    def tearDown(self):
        self.tmp.cleanup()

    def build(self, prune=True, tree='t'):
        with open(os.devnull, 'w', errors='backslashreplace') as null:     # like sys.stderr
            old = sys.stdout, sys.stderr
            sys.stdout = sys.stderr = null
            try:
                fm.build(self.root, self.key, tree, prune=prune)
            finally:
                sys.stdout, sys.stderr = old
        return parse(os.path.join(self.root, 'fastdl.manifest'), self.k)

    def test_keygen(self):
        self.assertEqual(stat.S_IMODE(os.stat(self.key).st_mode), 0o600)
        with self.assertRaises(SystemExit):
            fm.keygen(self.key)          # never overwrites a key

    def test_hostile_tree(self):
        r = self.root
        outside = os.path.join(self.d, 'outside.bsp')
        write(outside, BSP)
        write(f'{r}/maps/ok.bsp', BSP)
        write(f'{r}/maps/A.BSP', BSP)
        write(f'{r}/maps/a.bsp', BSP + b'2')                  # case collision: lowercase kept
        write(f'{r}/maps/empty.bsp', b'')
        write(f'{r}/maps/x.cfg', b'rcon_password x')
        write(f'{r}/maps/a b.bsp', BSP)
        write(f'{r}/maps/n\nl.bsp', BSP)
        write(f'{r}/sound/x.txt', b'x')
        write(f'{r}/cl_dlls/client.wav', b'RIFF')
        os.symlink(outside, f'{r}/maps/link.bsp')               # symlinked file
        os.symlink(self.d, f'{r}/sound/up')                   # symlinked dir pointing above the tree
        os.mkfifo(f'{r}/maps/fifo.bsp')
        with open(f'{r}/maps/big.bsp', 'wb') as f:             # sparse, one byte over the limit
            f.truncate(64 * 1024 * 1024 + 1)
        fb = os.fsencode(r) + b'/maps/\xff\xfe.bsp'
        with open(fb, 'wb') as f:
            f.write(BSP)
        entries = self.build()
        self.assertEqual([p for _, _, p in entries], ['maps/a.bsp', 'maps/ok.bsp'])
        self.assertEqual(entries[0][0], hashlib.blake2b(BSP + b'2', digest_size=32).hexdigest())
        left = sorted(os.path.relpath(os.path.join(dp, f), r) for dp, _, fs in os.walk(r) for f in fs)
        self.assertEqual(left, ['fastdl.manifest', 'maps/a.bsp', 'maps/ok.bsp'])   # pruned, symlinks too
        self.assertTrue(os.path.exists(outside))
        self.assertEqual(stat.S_IMODE(os.stat(f'{r}/fastdl.manifest').st_mode), 0o644)

    def test_order_matches_client(self):
        names = ['maps/a-b.bsp', 'maps/a.bsp', 'maps/a_b.bsp', 'maps/A0.bsp', 'maps/ab.bsp', 'sound/a-b.wav',
                 'sound/a.wav', 'sound/a/b.wav', 'sound/a_b.wav', 'sound/[x].wav', 'sound/(x).wav', 'sound/~x.wav']
        for n in names:
            write(os.path.join(self.root, n), b'RIFF' if n.endswith('.wav') else BSP)
        paths = [p for _, _, p in self.build()]
        low = [p.lower() for p in paths]
        self.assertEqual(low, sorted(low, key=lambda s: s.encode()))        # fdl_path_cmp order
        self.assertNotIn('sound/~x.wav', low)                               # '~' never fetched

    def test_bad_tree_name(self):
        for t in ['', '.x', 'a/b', 'a' * 33]:
            with self.assertRaises(SystemExit):
                self.build(tree=t)

    def test_gap_content_matches_type(self):
        # a config renamed to an allowed type is published today; the client would reject it after the
        # download ("unexpected file content", counts as an error) - the builder should skip it
        write(f'{self.root}/maps/backup.bsp', b'rcon_password "secret"\n')
        write(f'{self.root}/maps/ok.bsp', BSP)
        self.assertEqual([p for _, _, p in self.build()], ['maps/ok.bsp'])

    def test_gap_world_readable_key_refused(self):
        os.chmod(self.key, 0o644)
        write(f'{self.root}/maps/ok.bsp', BSP)
        with self.assertRaises(SystemExit):
            self.build()


class MkFastdl(unittest.TestCase):
    """tools/mkfastdl.sh end to end on a hostile mod folder"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        d = self.d = self.tmp.name
        m = self.mod = os.path.join(d, 'data', 'cstrike')
        self.out = os.path.join(d, 'data', 'fastdl-won', 'dl')
        self.key = os.path.join(d, 'data', 'fastdl-won', 'keys', 'fastdl.key')
        write(f'{d}/outside/secret.bsp', BSP)
        write(f'{m}/liblist.gam', b'game "x"')
        write(f'{m}/server.cfg', b'rcon_password "SECRET"\n', 0o644)
        write(f'{m}/maps/ok.bsp', BSP)
        write(f'{m}/maps/-rf.bsp', BSP)
        write(f'{m}/sound/x/$(touch PWNED).wav', b'RIFF')
        write(f'{m}/sound/x/`touch PWNED2`.wav', b'RIFF')
        write(f'{m}/sprites/;id;.spr', b'IDSP')
        write(f'{m}/maps/x.cfg', b'x')
        write(f'{m}/addons/amxmodx/x.wav', b'RIFF')
        write(f'{m}/logs/l.txt', b'x')
        os.symlink(f'{d}/outside/secret.bsp', f'{m}/maps/link.bsp')
        os.symlink(f'{d}/outside', f'{m}/maps/outdir')

    def tearDown(self):
        self.tmp.cleanup()

    def run_mk(self):
        env = dict(os.environ, FASTDL_KEY=self.key, FASTDL_OUT=self.out)
        return subprocess.run([os.path.join(HERE, 'mkfastdl.sh'), 'cstrike', self.mod], env=env, cwd=self.d,
                              capture_output=True, text=True)

    def tree_files(self):
        t = os.path.join(self.out, 'cstrike')
        return sorted(os.path.relpath(os.path.join(dp, f), t) for dp, _, fs in os.walk(t, followlinks=False) for f in fs)

    def test_hostile_folder(self):
        r = self.run_mk()
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(self.tree_files(), ['fastdl.manifest', 'maps/-rf.bsp', 'maps/ok.bsp'])
        for p in (self.d, self.mod, self.out, os.path.join(self.mod, 'sound', 'x')):
            self.assertFalse(os.path.exists(os.path.join(p, 'PWNED')) or os.path.exists(os.path.join(p, 'PWNED2')))
        self.assertEqual(stat.S_IMODE(os.stat(os.path.dirname(self.key)).st_mode) & 0o077, 0)
        gen = os.path.realpath(os.path.join(self.out, 'cstrike'))
        self.assertEqual(stat.S_IMODE(os.stat(gen).st_mode), 0o755)
        # second and third build: the previous generation is kept, older ones are removed
        first = gen
        self.assertEqual(self.run_mk().returncode, 0)
        second = os.path.realpath(os.path.join(self.out, 'cstrike'))
        self.assertTrue(os.path.isdir(first))
        self.assertEqual(self.run_mk().returncode, 0)
        self.assertFalse(os.path.exists(first))
        self.assertTrue(os.path.isdir(second))

    def test_bad_name_refused(self):
        env = dict(os.environ, FASTDL_KEY=self.key, FASTDL_OUT=self.out)
        for n in ['../x', 'a/b', 'A', '', 'x' * 33, 'a b', '.x', 'a\nb']:
            r = subprocess.run([os.path.join(HERE, 'mkfastdl.sh'), n, self.mod], env=env, capture_output=True)
            self.assertNotEqual(r.returncode, 0, n)

    def test_gap_hardlinked_config_not_published(self):
        # a hardlink of server.cfg (rcon_password) under an allowed name is published and served today
        os.link(f'{self.mod}/server.cfg', f'{self.mod}/maps/notes.txt')
        os.link(f'{self.mod}/server.cfg', f'{self.mod}/maps/fake.bsp')
        self.assertEqual(self.run_mk().returncode, 0)
        self.assertEqual(self.tree_files(), ['fastdl.manifest', 'maps/-rf.bsp', 'maps/ok.bsp'])

    def test_gap_hardlinked_key_not_published(self):
        self.assertEqual(self.run_mk().returncode, 0)        # creates the key
        os.link(self.key, f'{self.mod}/maps/k.txt')
        self.assertEqual(self.run_mk().returncode, 0)
        self.assertNotIn('maps/k.txt', self.tree_files())


class Deployment(unittest.TestCase):
    """static checks of what docker-compose.yml and fastdl.conf expose"""

    def read(self, rel):
        return open(os.path.join(SERVER, rel)).read()

    def test_compose(self):
        c = self.read('docker-compose.yml')
        web = c[c.index('\n  web:'):]
        build = c[c.index('\n  build:'):c.index('\n  web:')]
        for part in (web, build):
            self.assertIn('cap_drop: [ALL]', part)
            self.assertIn('no-new-privileges:true', part)
            self.assertIn('read_only: true', part)
        self.assertIn('user: "101:101"', web)
        self.assertIn('network_mode: none', build)
        self.assertRegex(web, r'source: "[^"]*/fastdl-won/dl", target: /usr/share/nginx/html, read_only: true')
        # the build starts as root only to chown the web service's new mount folders, then drops to the owner
        self.assertIn('cap_add: [CHOWN, SETUID, SETGID]', build)
        self.assertNotIn('cap_add', web)
        self.assertNotIn('keys', web.split('healthcheck')[0])             # the key never reaches nginx
        self.assertIn('@sha256:', web)

    def test_nginx(self):
        for f in ('web/fastdl.conf', 'web/fastdl-tls.conf'):
            c = self.read(f)
            locs = [ln.strip() for ln in c.splitlines() if ln.strip().startswith('location')]
            regex = [ln for ln in locs if ln.startswith('location ~')]
            self.assertTrue(regex[0].startswith('location ~ /\\.'), f)      # dot files first: generations, .skipped
            self.assertEqual(locs[-1], 'location / { return 404; }')
            for k in ('autoindex off;', 'disable_symlinks on', 'GET|HEAD', 'client_max_body_size 1k;', 'types { }'):
                self.assertIn(k, c, f)


if __name__ == '__main__':
    unittest.main(verbosity=1)
