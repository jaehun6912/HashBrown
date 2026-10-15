"""Local integration check; run after `make -C src` on Linux/WSL."""
from pathlib import Path
import concurrent.futures
import os
import shutil
import signal
import socket
import subprocess
import tempfile
import time

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / 'src' / 'build'


def openssl(*args):
    subprocess.run(['openssl', *map(str, args)], check=True, capture_output=True)


def main():
    # Refuse to interfere with an existing server.
    with socket.socket() as probe:
        probe.bind(('127.0.0.1', 10101))
    with tempfile.TemporaryDirectory(prefix='capstone-smoke-') as tmp:
        base = Path(tmp)
        server = base / 'server'
        server.mkdir()
        (server / 'clients').mkdir()
        (server / 'Files').mkdir()
        openssl('genpkey', '-algorithm', 'ed25519', '-out', server / 'server_private.pem')
        public = base / 'server_public.pem'
        openssl('pkey', '-in', server / 'server_private.pem', '-pubout', '-out', public)

        def client_dir(name, registered=True):
            folder = base / name
            folder.mkdir()
            (folder / 'Files').mkdir()
            shutil.copy(public, folder / 'server_public.pem')
            openssl('genpkey', '-algorithm', 'ed25519', '-out', folder / 'client_private.pem')
            if registered:
                openssl('pkey', '-in', folder / 'client_private.pem', '-pubout',
                        '-out', server / 'clients' / (name + '.pem'))
            return folder

        sender = client_dir('sender')
        receiver = client_dir('receiver')
        unknown = client_dir('unknown', False)
        payload = bytes(range(256)) * 1024 + b'capstone\x00\xff'
        (sender / 'Files' / 'payload.bin').write_bytes(payload)
        (sender / 'Files' / 'empty.bin').write_bytes(b'')

        def run_client(folder, commands, expected=0):
            result = subprocess.run([str(BIN / 'client')], cwd=folder,
                                    input='127.0.0.1\n10101\n' + commands,
                                    text=True, capture_output=True, timeout=20)
            assert result.returncode == expected, result.stdout + result.stderr
            return result.stdout

        with (base / 'server.log').open('w') as log:
            proc = subprocess.Popen([str(BIN / 'server')], cwd=server,
                                    stdout=log, stderr=log, start_new_session=True)
            try:
                deadline = time.monotonic() + 5
                while True:
                    assert proc.poll() is None, 'server exited before readiness'
                    try:
                        with socket.create_connection(('127.0.0.1', 10101), timeout=.2):
                            break
                    except OSError:
                        if time.monotonic() > deadline:
                            raise
                        time.sleep(.05)
                upload = run_client(sender, '1\n1\n1\n2\n3\n0\n')
                assert upload.count('[업로드(검증) 완료]') == 2, upload
                assert (server / 'Files' / 'payload.bin').read_bytes() == payload
                assert (server / 'Files' / 'empty.bin').read_bytes() == b''
                download = run_client(receiver, '2\n1\n2\n2\n0\n')
                assert (receiver / 'Files' / 'payload.bin').read_bytes() == payload, download
                assert (receiver / 'Files' / 'empty.bin').read_bytes() == b'', download
                assert 'AES-256-GCM 복호화/인증: 성공' in download, download
                run_client(unknown, '0\n', expected=1)
                wrong_server = client_dir('wrong-server')
                openssl('pkey', '-in', unknown / 'client_private.pem', '-pubout',
                        '-out', wrong_server / 'server_public.pem')
                run_client(wrong_server, '0\n', expected=1)
                with concurrent.futures.ThreadPoolExecutor(max_workers=2) as pool:
                    outputs = list(pool.map(lambda folder: run_client(folder, '3\n0\n'),
                                            [sender, receiver]))
                assert all('AES-256-GCM 복호화/인증: 성공' in out for out in outputs)
                assert not list(server.rglob('*.tmp'))
                print('PASS: multi-chunk and empty-file upload/download, exact bytes, '
                      'encrypted lists, unregistered client rejection, wrong server key '
                      'rejection, concurrent client invocations, temporary-file cleanup')
            finally:
                if proc.poll() is None:
                    os.killpg(proc.pid, signal.SIGTERM)
                proc.wait(timeout=5)


if __name__ == '__main__':
    main()
