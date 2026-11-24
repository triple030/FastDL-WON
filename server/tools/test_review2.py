#!/usr/bin/env python3
"""Review 2 (independent pass): negative tests of the builder against a hostile data folder.
usage: python3 -I tools/test_review2.py
Tests named test_gap_* describe a rule the tools do not enforce yet (REVIEW.md, review2) and fail until fixed."""
import os, subprocess, sys, tempfile, unittest

HERE = os.path.dirname(os.path.abspath(__file__))
sys.path.insert(0, HERE)
import fastdl_manifest as fm  # noqa: E402

BSP = b'\x1e\0\0\0' + b'm' * 20
WAV = b'RIFF\0\0\0\0WAVEfmt '


def write(path, data, mode=None):
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'wb') as f:
        f.write(data)
    if mode is not None:
        os.chmod(path, mode)


def entries(manifest):
    """strict client-like parse: every line between the tree line and sig must be '<64 hex> <size> <path>' with a
    path the client fetches; returns the paths or raises"""
    with open(manifest, 'rb') as f:
        lines = f.read().split(b'\n')
    assert lines[0] == b'FASTDL-WON1' and lines[1].startswith(b'tree ') and lines[-2].startswith(b'sig ')
    out = []
    for ln in lines[2:-2]:
        h, s, p = ln.decode().split(' ', 2)
        if len(h) != 64 or fm.limit_for(p) is None or '\n' in p:
            raise ValueError(f'line the client rejects: {ln!r}')
        out.append(p)
    return out


class Review2(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.d = self.tmp.name
        self.data = os.path.join(self.d, 'data')
        self.mod = os.path.join(self.data, 'cstrike')
        self.web = os.path.join(self.data, 'fastdl-won', 'dl')
        self.keys = os.path.join(self.d, 'keys')
        write(os.path.join(self.mod, 'liblist.gam'), b'game "x"\n')
        write(os.path.join(self.mod, 'server.cfg'), b'rcon_password "SECRET_CS"\n')
        write(os.path.join(self.mod, 'maps', 'ok.bsp'), BSP)

    def tearDown(self):
        self.tmp.cleanup()

    def build(self):
        env = dict(os.environ, FASTDL_KEY=os.path.join(self.keys, 'fastdl.key'), FASTDL_OUT=self.web)
        r = subprocess.run([os.path.join(HERE, 'mkfastdl.sh'), 'cstrike', self.mod], env=env, capture_output=True, text=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        return os.path.join(self.web, 'cstrike', 'fastdl.manifest')

    def test_newline_rule(self):
        self.assertIsNone(fm.limit_for('maps/x\n.bsp'))
        self.assertIsNone(fm.limit_for('maps/x.bsp\n'))

    def test_gap_newline_in_directory(self):
        # COMP uses re.match with '$', which matches before a final newline: a directory "a\n" passes
        for p in ['sound/a\n/x.wav', 'models/p\n/x.mdl', 'sprites/nul\n/x.spr', 'gfx/x.\n/a.tga']:
            self.assertIsNone(fm.limit_for(p), repr(p))

    def test_gap_newline_directory_breaks_manifest(self):
        # one directory with a newline in its name makes every client reject the whole manifest
        write(os.path.join(self.mod, 'sound', 'a\n', 'x.wav'), WAV)
        entries(self.build())

    def test_hardlinks_inside_mod_and_key_skipped(self):
        m = self.build()  # creates the key
        os.link(os.path.join(self.mod, 'server.cfg'), os.path.join(self.mod, 'maps', 'cfg.txt'))
        os.link(os.path.join(self.mod, 'liblist.gam'), os.path.join(self.mod, 'maps', 'gam.txt'))
        os.link(os.path.join(self.keys, 'fastdl.key'), os.path.join(self.mod, 'maps', 'key.txt'))
        os.symlink('../server.cfg', os.path.join(self.mod, 'maps', 'sym.txt'))
        os.symlink('..', os.path.join(self.mod, 'sound'))
        m = self.build()
        self.assertEqual(entries(m), ['maps/ok.bsp'])

    def test_gap_hardlink_from_outside_the_mod_folder(self):
        # another mod's server.cfg or any other file of the data folder (or of the host file system) hardlinked
        # under an allowed text name is listed and served: the deny list only covers the mod folder and the key
        write(os.path.join(self.data, 'dmc', 'server.cfg'), b'rcon_password "SECRET_DMC"\n')
        write(os.path.join(self.d, 'elsewhere', '.env'), b'DB_PASSWORD=SECRET\n')
        os.link(os.path.join(self.data, 'dmc', 'server.cfg'), os.path.join(self.mod, 'maps', 'dmc.txt'))
        os.makedirs(os.path.join(self.mod, 'overviews'))
        os.link(os.path.join(self.d, 'elsewhere', '.env'), os.path.join(self.mod, 'overviews', 'env.txt'))
        self.assertEqual(entries(self.build()), ['maps/ok.bsp'])

    def test_wrong_content_skipped(self):
        write(os.path.join(self.mod, 'maps', 'cfg.bsp'), b'rcon_password "x"\n')
        write(os.path.join(self.mod, 'sound', 'elf.wav'), b'\x7fELF\1\1\1' + b'\0' * 20)
        write(os.path.join(self.mod, 'gfx', 'pe.bmp'), b'MZ\x90\0' + b'\0' * 20)
        write(os.path.join(self.mod, 'maps', 'bin.txt'), b'a\0b')
        write(os.path.join(self.mod, 'maps', 'CON.bsp'), BSP)
        write(os.path.join(self.mod, 'maps', 'LONGNA~1.bsp'), BSP)
        write(os.path.join(self.mod, 'maps', 'x.bsp.'), BSP)
        write(os.path.join(self.mod, 'maps', 'a b.bsp'), BSP)
        write(os.path.join(self.mod, 'maps', 'ä.bsp'), BSP)
        write(os.path.join(self.mod, 'maps', 'x.bsp:ads'), BSP)
        write(os.path.join(self.mod, 'addons', 'x.wav'), WAV)
        write(os.path.join(self.mod, 'cl_dlls', 'x.wav'), WAV)
        write(os.path.join(self.mod, 'logs', 'x.txt'), b'log')
        self.assertEqual(entries(self.build()), ['maps/ok.bsp'])

    def test_gap_unreadable_file_listed(self):
        # a file nginx (uid 101, group FASTDL_GID) cannot read is listed: every client then counts an error
        write(os.path.join(self.mod, 'maps', 'priv.bsp'), BSP, mode=0o600)
        self.assertEqual(entries(self.build()), ['maps/ok.bsp'])


if __name__ == '__main__':
    unittest.main(verbosity=2)
