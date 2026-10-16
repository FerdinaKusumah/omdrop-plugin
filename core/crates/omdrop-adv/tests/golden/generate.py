#!/usr/bin/env python3
"""Regenerate python.json and the *.cms records from the Python advertisers.

The Rust builders must match these byte for byte. Run from anywhere:

    python3 crates/omdrop-adv/tests/golden/generate.py [~/Projects/omdrop-awdl]

The Python functions are imported and called, never main(): nothing is sent.
`ble-airdrop-adv.py` imports dbus and gi at top level; stubs stand in for them
so this runs without either installed.
"""
import importlib
import json
import plistlib
import socket
import struct
import subprocess
import sys
import tempfile
import types
from pathlib import Path

HERE = Path(__file__).resolve().parent
AWDL = Path(sys.argv[1] if len(sys.argv) > 1 else '~/Projects/omdrop-awdl').expanduser()
sys.path.insert(0, str(AWDL / 'userspace'))
sys.dont_write_bytecode = True  # the source checkout is read-only to us

for name in ('dbus', 'dbus.mainloop', 'dbus.mainloop.glib', 'dbus.service', 'gi', 'gi.repository'):
    sys.modules[name] = types.ModuleType(name)
sys.modules['dbus'].service = sys.modules['dbus.service']
sys.modules['dbus'].mainloop = sys.modules['dbus.mainloop']
sys.modules['dbus.mainloop'].glib = sys.modules['dbus.mainloop.glib']
sys.modules['gi'].repository = sys.modules['gi.repository']
sys.modules['dbus.service'].Object = object
sys.modules['dbus.service'].method = lambda *a, **k: (lambda f: f)
sys.modules['gi.repository'].GLib = None

adv = importlib.import_module('awdl-airdrop-adv')
mdns = importlib.import_module('awdl-mdns-respond')
ble = importlib.import_module('ble-airdrop-adv')

out = {}

# --- BLE payload and redaction -------------------------------------------------
cases = []
for arm in ('A', 'V2', 'B'):
    for tlv, hashes, tag in ((5, '0000000000000000', '000000'),
                             (5, '0102030405060708', 'aabbcc'),
                             (0x7e, 'ffeeddccbbaa9988', '010203'),
                             (5, '01 02 03 04 05 06 07 08', 'AbCdEf')):
        value = ble.payload(arm, tlv, hashes, tag)
        cases.append({'arm': arm, 'type': tlv, 'hashes': hashes, 'tag': tag,
                      'value': value.hex(), 'redacted': ble.redact(value)})
out['ble_payload'] = cases

errors = []
for hashes, tag in (('0102', 'aabbcc'), ('0102030405060708', 'aabb')):
    try:
        ble.payload('A', 5, hashes, tag)
    except SystemExit as e:
        errors.append({'hashes': hashes, 'tag': tag, 'error': str(e)})
out['ble_payload_errors'] = errors

# --- hashes_from_record over real CMS-signed plists ----------------------------
def h(prefix):
    return prefix + 'f' * (64 - len(prefix))

records = {
    'full': {'altDsID': 'X', 'ValidatedEmailHashes': [h('1111'), h('2222'), h('3333'), h('4444'), h('5555')],
             'ValidatedPhoneHashes': [h('AAAA'), h('bbbb')]},
    'phones-only': {'ValidatedPhoneHashes': [h('aaaa'), h('bbbb'), h('cccc')]},
    'one-email': {'ValidatedEmailHashes': [h('1234')]},
    'mixed-types': {'ValidatedEmailHashes': [7, h('ABCD'), b'xx', h('ef01')], 'ValidatedPhoneHashes': False},
    'none': {'ValidatedEmailHashes': [], 'altDsID': 'X'},
    'short-hash': {'ValidatedEmailHashes': ['12', h('3456')]},
}
record_cases = []
with tempfile.TemporaryDirectory() as tmp:
    tmp = Path(tmp)
    subprocess.run(['openssl', 'req', '-newkey', 'rsa:2048', '-nodes', '-x509', '-days', '1',
                    '-subj', '/CN=omdrop golden', '-keyout', tmp / 'k.pem', '-out', tmp / 'c.pem'],
                   check=True, capture_output=True)
    for name, plist in sorted(records.items()):
        for fmt in (plistlib.FMT_XML, plistlib.FMT_BINARY):
            if fmt == plistlib.FMT_BINARY and name != 'full':
                continue
            body = tmp / 'body'
            body.write_bytes(plistlib.dumps(plist, fmt=fmt))
            suffix = '' if fmt == plistlib.FMT_XML else '-binary'
            der = HERE / f'record-{name}{suffix}.cms'
            subprocess.run(['openssl', 'cms', '-sign', '-in', body, '-signer', tmp / 'c.pem',
                            '-inkey', tmp / 'k.pem', '-outform', 'DER', '-nodetach', '-binary',
                            '-out', der], check=True, capture_output=True)
            case = {'file': der.name}
            try:
                hashes, count = ble.hashes_from_record(der.read_bytes())
                case.update(hashes=hashes, identifiers=count)
            except SystemExit as e:
                case.update(error=str(e))
            record_cases.append(case)
out['ble_records'] = record_cases

# --- AWDL announcement builders ------------------------------------------------
macs = ['a1b2c3d4e5f6', '000000000000', 'fefefefefefe', '0217f2010203']
out['eui64'] = [{'mac': m, 'll': adv.eui64_ll(bytes.fromhex(m)).hex()} for m in macs]
names = ['_airdrop._tcp.local', 'a.b.', '.x..y.', '', 'abc123._airdrop._tcp.local', 'mac-awdl.local']
out['dname'] = [{'name': n, 'wire': adv.dname(n).hex()} for n in names]
out['csum16'] = [{'data': d.hex(), 'sum': adv.csum16(d)} for d in
                 (b'', b'\x01', b'\xff\xff', b'\x00\x01\xf2\x03\xf4\xf5\xf6\xf7', bytes(range(255)), b'\xff' * 1001)]
out['rr'] = [{'name': n, 'type': t, 'class': c, 'ttl': ttl, 'rdata': r.hex(),
              'wire': adv.rr(n, t, c, ttl, r).hex()}
             for n, t, c, ttl, r in (('_airdrop._tcp.local', 12, 1, 4500, b'\x03abc\x00'),
                                     ('host.local', 28, 0x8001, 120, bytes(16)),
                                     ('x', 16, 0x8001, 0xffffffff, b''))]

ann = []
for sid, host, port, flags, mac in (('a1b2c3d4e5f6', 'mac-awdl.local', 8771, 0x3fb, 'a1b2c3d4e5f6'),
                                     ('0123456789ab', 'omdrop-awdl.local', 8770, 136, '0217f2010203'),
                                     ('x', 'h.local.', 0, 0, '000000000000'),
                                     ('abcdef012345', 'my-host.local', 65535, 4294967295, 'fefefefefefe')):
    ll = adv.eui64_ll(bytes.fromhex(mac))
    dst6 = socket.inet_pton(socket.AF_INET6, 'ff02::fb')
    msg = adv.announcement(sid, host, port, flags, ll)
    payload = adv.udp6(ll, dst6, msg)
    # The responder's reply: the announcement plus an NSEC, built exactly as
    # awdl-mdns-respond.py's main() builds it.
    nsec = adv.rr(host, 47, adv.CACHE_FLUSH, 120, adv.dname(host) + b'\x00\x06' + bytes([0, 0, 0, 0x08, 0, 0x01]))
    ancount = struct.unpack('!H', msg[6:8])[0] + 1
    reply = msg[:6] + struct.pack('!H', ancount) + msg[8:] + nsec
    ann.append({'sid': sid, 'host': host, 'port': port, 'flags': flags, 'mac': mac,
                'announcement': msg.hex(), 'udp6': payload.hex(),
                'snap': [{'seq': s, 'frame': adv.wrap(bytes.fromhex(mac), payload, s).hex()} for s in (0, 1, 0x4000, 0xffff)],
                'plain': adv.wrap(bytes.fromhex(mac), payload, 7, snap=False).hex(),
                'reply': reply.hex(), 'reply_udp6': adv.udp6(ll, dst6, reply).hex()})
out['announcement'] = ann

# The --dump text, through main() on the loopback interface (MAC 00:..:00).
dump = []
for extra in ([], ['--plain'], ['--seq', '300', '--port', '1234', '--flags', '136', '--service-id', 'abc']):
    argv = ['--iface', 'lo', '--dump', '--host', 'golden-awdl.local', *extra]
    text = subprocess.run([sys.executable, AWDL / 'userspace/awdl-airdrop-adv.py', *argv],
                          check=True, capture_output=True, text=True).stdout
    dump.append({'argv': argv, 'stdout': text})
out['announce_dump'] = dump

# --- responder parsing ---------------------------------------------------------
def query(*names, flags=0, qd=None, tail=b''):
    body = b''.join(adv.dname(n) + b'\x00\x01\x00\x01' for n in names)
    return struct.pack('!HHHHHH', 0, flags, len(names) if qd is None else qd, 0, 0, 0) + body + tail

dns_cases = [
    query('_airdrop._tcp.local'),
    query('Mac-AWDL.local', 'x._AirDrop._tcp.local'),
    query('a.local', flags=0x8400),
    query(qd=0),
    query('a.local', qd=3),
    bytes(11),
    # Compressed: second question points at the first name's 'local' label.
    struct.pack('!HHHHHH', 0, 0, 2, 0, 0, 0) + adv.dname('host.local') + b'\x00\x01\x00\x01'
    + b'\x02xy\xc0\x11' + b'\x00\x01\x00\x01',
    # Pointer loop.
    struct.pack('!HHHHHH', 0, 0, 1, 0, 0, 0) + b'\xc0\x0c',
    # Non-ASCII label bytes are replaced, then lowercased.
    struct.pack('!HHHHHH', 0, 0, 1, 0, 0, 0) + b'\x03A\xffZ\x05LOCAL\x00\x00\x01\x00\x01',
    # Truncated label.
    struct.pack('!HHHHHH', 0, 0, 1, 0, 0, 0) + b'\x09abc',
    # Missing qtype/qclass on the last question is tolerated.
    struct.pack('!HHHHHH', 0, 0, 1, 0, 0, 0) + b'\x01a\x00',
    # Reserved label type 0x40 is read as a 64-byte label.
    struct.pack('!HHHHHH', 0, 0, 1, 0, 0, 0) + b'\x40' + b'b' * 64 + b'\x00\x00\x01\x00\x01',
]
out['questions'] = [{'dns': d.hex(), 'names': mdns.questions(d)} for d in dns_cases]

src = bytes.fromhex('020304050607')
ip6_udp = lambda nh, dport, dns: (struct.pack('!IHBB', 0x60000000, 8 + len(dns), nh, 255) + bytes(32)
                                  + struct.pack('!HHHH', 5353, dport, 8 + len(dns), 0) + dns)
q = query('_airdrop._tcp.local')
frames = [
    b'\x33\x33\x00\x00\x00\xfb' + src + b'\x86\xdd' + ip6_udp(17, 5353, q),
    adv.wrap(src, ip6_udp(17, 5353, q), 5),
    b'\x33\x33\x00\x00\x00\xfb' + src + b'\x86\xdd' + ip6_udp(6, 5353, q),
    b'\x33\x33\x00\x00\x00\xfb' + src + b'\x86\xdd' + ip6_udp(17, 53, q),
    b'\x33\x33\x00\x00\x00\xfb' + src + b'\x08\x00' + ip6_udp(17, 5353, q),
    b'\x33\x33\x00\x00\x00\xfb' + src + b'\x86\xdd' + ip6_udp(17, 5353, q)[:47],
    adv.wrap(src, ip6_udp(17, 5353, q), 5)[:29],
    bytes(13),
    bytes(14),
    # SNAP with the wrong OUI.
    adv.wrap(src, ip6_udp(17, 5353, q), 5).replace(b'\x00\x17\xf2', b'\x00\x17\xf3', 1),
    # SNAP header with a length type above 1500 is not SNAP.
    b'\x33\x33\x00\x00\x00\xfb' + src + b'\x06\x00\xaa\xaa\x03' + bytes(60),
    # Empty DNS payload is still an mDNS frame.
    b'\x33\x33\x00\x00\x00\xfb' + src + b'\x86\xdd' + ip6_udp(17, 5353, b''),
]
result = []
for f in frames:
    got = mdns.mdns_payload(f)
    result.append({'frame': f.hex(), 'src': got[0].hex() if got else None, 'dns': got[1].hex() if got else None})
out['mdns_payload'] = result

(HERE / 'python.json').write_text(json.dumps(out, indent=1, sort_keys=True) + '\n')
print(f'wrote {HERE / "python.json"}')
