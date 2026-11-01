"""Cloud-only encrypted snapshot reader, with no process scanning or source writes.

Crypto functions below are copied unchanged from xwechat/src/wechat_decrypt_tool/
wechat_decrypt.py; controlled WAL helper changes are recorded in VENDOR_PROVENANCE.md.
Caller must enforce the expected cloud host before invoking this module.
"""
from contextlib import closing, ExitStack
import hashlib
import hmac
import logging
import os
from pathlib import Path
import re
import sqlite3
import stat
import time

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import zstandard

from vendor.xwechat.sqlite_wal import merge_wal_snapshot
from vendor.xwechat.windows_wal_capture import WalCaptureError, pin_wal_files

SQLITE_HEADER = b"SQLite format 3\x00"
PAGE_SIZE = 4096
KEY_SIZE = 32
SALT_SIZE = 16
IV_SIZE = 16
HMAC_SIZE = 64
RESERVE_SIZE = IV_SIZE + HMAC_SIZE
MAX_CAPTURE_BYTES = 64 * 1024 * 1024
CAPTURE_LOCK_TIMEOUT_SECONDS = 2.0
logger = logging.getLogger(__name__)


class CaptureBusyTimeout(WalCaptureError):
    code = 'CLOUD_SOURCE_BUSY'


def _derive_mac_key(enc_key: bytes, salt: bytes) -> bytes:
    """Derive SQLCipher/WCDB page HMAC key."""
    mac_salt = bytes(b ^ 0x3A for b in salt)
    return hashlib.pbkdf2_hmac("sha512", enc_key, mac_salt, 2, dklen=KEY_SIZE)


def _derive_sqlcipher_enc_key(key_material: bytes, salt: bytes) -> bytes:
    """Derive AES enc_key from SQLCipher passphrase/base key."""
    return hashlib.pbkdf2_hmac("sha512", key_material, salt, 256000, dklen=KEY_SIZE)


def _compute_page_hmac(mac_key: bytes, page: bytes, page_num: int) -> bytes:
    offset = SALT_SIZE if page_num == 1 else 0
    data_end = PAGE_SIZE - RESERVE_SIZE + IV_SIZE
    mac = hmac.new(mac_key, digestmod=hashlib.sha512)
    mac.update(page[offset:data_end])
    mac.update(page_num.to_bytes(4, "little"))
    return mac.digest()


def _resolve_page1_key_material(key_material: bytes, page1: bytes) -> tuple[bytes, bytes, str] | None:
    """Detect whether input key is raw enc_key or SQLCipher passphrase by page-1 HMAC."""
    if len(page1) < PAGE_SIZE:
        return None

    salt = page1[:SALT_SIZE]
    stored_page1_hmac = page1[PAGE_SIZE - HMAC_SIZE: PAGE_SIZE]
    candidates = [
        ("raw_enc_key", key_material, _derive_mac_key(key_material, salt)),
    ]

    derived_key = _derive_sqlcipher_enc_key(key_material, salt)
    candidates.append(("sqlcipher_passphrase", derived_key, _derive_mac_key(derived_key, salt)))

    for mode, enc_key, mac_key in candidates:
        if hmac.compare_digest(stored_page1_hmac, _compute_page_hmac(mac_key, page1, 1)):
            return enc_key, mac_key, mode

    return None


def _decrypt_page(enc_key: bytes, page: bytes, page_num: int) -> bytes:
    iv = page[PAGE_SIZE - RESERVE_SIZE: PAGE_SIZE - RESERVE_SIZE + IV_SIZE]
    offset = SALT_SIZE if page_num == 1 else 0
    encrypted_page = page[offset: PAGE_SIZE - RESERVE_SIZE]

    cipher = Cipher(
        algorithms.AES(enc_key),
        modes.CBC(iv),
        backend=default_backend(),
    )
    decryptor = cipher.decryptor()
    decrypted_page = decryptor.update(encrypted_page) + decryptor.finalize()

    # Plain SQLite pages do not carry SQLCipher/WCDB IV/HMAC reserve bytes.
    # Keep page size stable by zero-filling the reserve tail.
    if page_num == 1:
        return SQLITE_HEADER + decrypted_page + (b"\x00" * RESERVE_SIZE)
    return decrypted_page + (b"\x00" * RESERVE_SIZE)


def _file_state(path: Path):
    try:
        info = path.lstat()
    except FileNotFoundError:
        return None
    if not stat.S_ISREG(info.st_mode) or (
            getattr(info, 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT):
        raise RuntimeError(f'Only ordinary source files are accepted: {path.name}')
    return info.st_dev, info.st_ino, info.st_size, info.st_mtime_ns


def _message_files(db_root: Path) -> list[Path]:
    directory = db_root / 'message'
    observed = sorted(directory.glob('message*.db'))
    files = [p for p in observed if p.name.lower() not in {'message_fts.db', 'message_resource.db'}]
    unknown = [p.name for p in files if not re.fullmatch(r'message_[0-9]+\.db', p.name.lower())]
    if unknown:
        raise RuntimeError(f'Unsupported message database names in {directory}: {unknown}')
    if not files:
        raise RuntimeError(f'No supported message shards in {directory}; observed: {[p.name for p in observed]}')
    return files


def database_paths(data_root: Path) -> dict[str, Path]:
    accounts = sorted(path for path in data_root.glob('*/db_storage') if path.is_dir())
    if len(accounts) != 1:
        raise RuntimeError(f'Expected one account db_storage, found {len(accounts)}')
    db_root = accounts[0]
    if any(path.is_symlink() or (
            getattr(path.lstat(), 'st_file_attributes', 0) & stat.FILE_ATTRIBUTE_REPARSE_POINT)
            for path in (data_root, db_root.parent, db_root)):
        raise RuntimeError('Linked account paths are not accepted')
    paths = {'db_root': db_root, 'session': db_root / 'session' / 'session.db',
             'contact': db_root / 'contact' / 'contact.db', 'message': _message_files(db_root)[0]}
    for role in ('session', 'contact', 'message'):
        if _file_state(paths[role]) is None:
            raise FileNotFoundError(f'Missing {role} database: {paths[role]}')
    return paths


def _read_stream(path, stream, size, *, allow_growth=False):
    before = os.fstat(stream.fileno())
    if size > MAX_CAPTURE_BYTES:
        raise RuntimeError('Snapshot capacity exceeds the 64 MiB limit')
    stream.seek(0)
    data = stream.read(size)
    stream.seek(0)
    repeated = stream.read(size)
    after = os.fstat(stream.fileno())
    fields = ('st_dev', 'st_ino') if allow_growth else ('st_dev', 'st_ino', 'st_size', 'st_mtime_ns')
    if (len(data) != size or data != repeated or before.st_size < size or after.st_size < size
            or any(getattr(before, f) != getattr(after, f) for f in fields)):
        raise RuntimeError(f'Source changed during capture: {path.name}')
    current = _file_state(path)
    if current is None or current[:2] != (after.st_dev, after.st_ino):
        raise RuntimeError(f'Source pathname was replaced: {path.name}')
    return data


def _capture_database(path: Path) -> tuple[bytes, bytes, dict]:
    started = time.monotonic()
    deadline = started + CAPTURE_LOCK_TIMEOUT_SECONDS
    last_busy = None
    while last_busy is None or time.monotonic() < deadline:
        try:
            captured = _capture_database_once(path)
        except WalCaptureError as exc:
            if exc.stage != 'source_busy':
                raise
            if last_busy is None:
                logger.warning('SQLite snapshot acquisition waiting: database=%s timeout_s=%.1f conflict=%s',
                               path.name, CAPTURE_LOCK_TIMEOUT_SECONDS, exc)
            last_busy = exc
            # Releasing the failed capture before waiting refreshes metadata after a checkpoint.
            remaining = deadline - time.monotonic()
            if remaining > 0:
                time.sleep(min(.05, remaining))
        else:
            if last_busy is not None:
                logger.info('SQLite snapshot acquired after contention: database=%s elapsed_s=%.3f',
                            path.name, time.monotonic() - started)
            return captured
    raise CaptureBusyTimeout('source_busy',
        f'SQLite snapshot acquisition timed out after {CAPTURE_LOCK_TIMEOUT_SECONDS:g}s: '
        f'{path.name}; last conflict: {last_busy}') from last_busy


def _capture_database_once(path: Path) -> tuple[bytes, bytes, dict]:
    siblings = {suffix: Path(str(path) + suffix) for suffix in ('', '-wal', '-shm', '-journal')}
    before = {suffix: _file_state(p) for suffix, p in siblings.items()}
    if before[''] is None:
        raise FileNotFoundError(path)
    with ExitStack() as stack:
        pinned, boundary = {}, None
        if before['-shm'] is not None:
            pinned, boundary = stack.enter_context(pin_wal_files(path))
        data = {}
        for suffix in ('', '-wal', '-journal'):
            source = siblings[suffix]
            if source in pinned:
                stream, size = pinned[source]
            elif before[suffix] is not None:
                stream = stack.enter_context(source.open('rb'))
                size = before[suffix][2]
            else:
                data[suffix] = b''
                continue
            data[suffix] = _read_stream(source, stream, size,
                                       allow_growth=boundary is not None and suffix == '-wal')
        if data['-journal'].startswith(bytes.fromhex('d9d505f920a163d7')):
            raise RuntimeError('Hot rollback journal requires recovery by WeChat')
        for suffix in ('', '-wal', '-journal'):
            current = _file_state(siblings[suffix])
            if boundary is not None and suffix == '-wal':
                if current is None or before[suffix] is None or current[:2] != before[suffix][:2]:
                    raise RuntimeError('Pinned WAL identity changed during capture')
            elif current != before[suffix]:
                raise RuntimeError(f'Source metadata changed during capture: {siblings[suffix].name}')
    after_shm = _file_state(siblings['-shm'])
    if (None if after_shm is None else after_shm[:2]) != (
            None if before['-shm'] is None else before['-shm'][:2]):
        raise RuntimeError('SHM presence or identity changed during capture')
    return data[''], data['-wal'], {'guarantee': 'per_database_committed_prefix' if boundary is not None
                                   else 'stable_observation', 'boundary': boundary}


def _page1_layout(header):
    pages = int.from_bytes(header[28:32], 'big')
    counter = int.from_bytes(header[24:28], 'big')
    valid_for = int.from_bytes(header[92:96], 'big')
    return {'header_database_pages': pages, 'page_size': int.from_bytes(header[16:18], 'big'),
            'reserved_bytes': header[20], 'file_change_counter': counter, 'version_valid_for': valid_for,
            'freelist_pages': int.from_bytes(header[36:40], 'big'),
            'auto_vacuum_root_page': int.from_bytes(header[52:56], 'big'),
            'header_size_valid': pages > 0 and counter == valid_for}


def _open_database(path: Path, key: bytes):
    encrypted, wal, capture = _capture_database(path)
    if len(encrypted) < PAGE_SIZE or len(encrypted) % PAGE_SIZE or encrypted.startswith(SQLITE_HEADER):
        raise ValueError(f'Expected complete encrypted 4096-byte pages: {path.name}')
    material = _resolve_page1_key_material(key, encrypted[:PAGE_SIZE])
    if material is None:
        raise ValueError(f'Page 1 HMAC authentication failed: {path.name}')
    enc_key, mac_key, mode = material
    layout = {'physical_pages': len(encrypted) // PAGE_SIZE,
              **_page1_layout(_decrypt_page(enc_key, encrypted[:PAGE_SIZE], 1)),
              'wal_bytes': len(wal), 'capture': capture}
    logical_pages = layout['header_database_pages']
    if layout['page_size'] != PAGE_SIZE or layout['reserved_bytes'] != RESERVE_SIZE:
        raise ValueError(f'Unsupported authenticated database header format: {path.name}; source_layout={layout}')
    if not layout['header_size_valid'] or logical_pages > layout['physical_pages']:
        raise ValueError(f'Unsupported authenticated database header size: {path.name}; source_layout={layout}')
    # SQLite's authenticated logical size excludes physical preallocation (file format section 1.3.7).
    layout['excluded_tail_pages'] = layout['physical_pages'] - logical_pages
    layout['excluded_tail_all_zero'] = not any(memoryview(encrypted)[logical_pages * PAGE_SIZE:])
    encrypted = encrypted[:logical_pages * PAGE_SIZE]
    for offset in range(0, len(encrypted), PAGE_SIZE):
        page = encrypted[offset:offset + PAGE_SIZE]
        if not hmac.compare_digest(page[-HMAC_SIZE:], _compute_page_hmac(mac_key, page, offset // PAGE_SIZE + 1)):
            raise ValueError(f'Source page {offset // PAGE_SIZE + 1} HMAC failed: {path.name}; '
                             f'all_zero={not any(page)}; source_layout={layout}')
    def committed_page_count(page):
        header = _page1_layout(_decrypt_page(enc_key, page, 1))
        layout['committed_page1'] = header
        if (header['page_size'] != PAGE_SIZE or header['reserved_bytes'] != RESERVE_SIZE
                or not header['header_size_valid']):
            raise ValueError(f'Unsupported authenticated committed database header: {header}')
        return header['header_database_pages']

    try:
        merged, wal_info = merge_wal_snapshot(encrypted, wal, PAGE_SIZE, verify_page=lambda page, number:
            hmac.compare_digest(page[-HMAC_SIZE:], _compute_page_hmac(mac_key, page, number)),
            database_page_count=committed_page_count)
    except ValueError as exc:
        raise ValueError(f'{path.name}: {exc}; source_layout={layout}') from exc
    plain = bytearray().join(_decrypt_page(enc_key, merged[i:i + PAGE_SIZE], i // PAGE_SIZE + 1)
                             for i in range(0, len(merged), PAGE_SIZE))
    plain[18:20] = b'\x01\x01'
    db = sqlite3.connect(':memory:')
    try:
        db.deserialize(plain)
        if db.execute('PRAGMA quick_check').fetchall() != [('ok',)]:
            raise sqlite3.DatabaseError(f'SQLite quick_check failed: {path.name}')
        db.execute('PRAGMA query_only=ON')
        db.row_factory = sqlite3.Row
    except BaseException:
        db.close()
        raise
    return db, {**capture, 'key_mode': mode, 'source_layout': layout, 'wal': wal_info}


def _decode_content(message, compressed) -> str:
    value = message if compressed in (None, b'', '') else compressed
    if isinstance(value, str):
        return value
    if not isinstance(value, bytes):
        raise ValueError('Unsupported text message storage type')
    if value.startswith(b'\x28\xb5\x2f\xfd'):
        value = zstandard.decompress(value, max_output_size=MAX_CAPTURE_BYTES)
    return value.decode('utf-8', errors='strict')


def read_target_samples(db_root: Path, key: bytes, target_group: str, token: str) -> dict:
    started = time.perf_counter()
    if not isinstance(key, bytes) or len(key) != KEY_SIZE:
        raise ValueError('A verified 32-byte database key is required')
    if not target_group or not re.fullmatch(r'WXPROBE_[A-Za-z0-9]+', token):
        raise ValueError('An exact target group and synthetic WXPROBE token are required')
    paths = database_paths(db_root.parent.parent)
    if paths['db_root'] != db_root:
        raise RuntimeError('Selected account source differs from discovered account')
    identity = re.fullmatch(r'(wxid_[A-Za-z0-9]+)(?:_[0-9a-fA-F]{4})?', db_root.parent.name)
    if identity is None:
        raise RuntimeError('Unsupported account folder identity format')
    self_id = identity[1]
    messages = _message_files(db_root)
    files = [paths['session'], paths['contact'], *messages]
    size = sum(state[2] for p in files for suffix in ('', '-wal', '-shm', '-journal')
               if (state := _file_state(Path(str(p) + suffix))) is not None)
    if size > MAX_CAPTURE_BYTES:
        raise RuntimeError('Snapshot capacity exceeds the 64 MiB limit')
    captures = {}
    session_db, captures[paths['session'].name] = _open_database(paths['session'], key)
    session_db.close()
    contact_db, captures[paths['contact'].name] = _open_database(paths['contact'], key)
    with closing(contact_db) as db:
        groups = db.execute("SELECT username FROM contact WHERE username LIKE '%@chatroom' AND "
            "CASE WHEN remark IS NOT NULL AND remark <> '' THEN remark ELSE nick_name END = ?",
            (target_group,)).fetchall()
    if len(groups) != 1:
        raise RuntimeError(f'Expected one exact target group, found {len(groups)}')
    group_id = groups[0]['username']
    expected_tables = {'Msg_' + hashlib.md5(group_id.encode('utf-8')).hexdigest(),
                       'Chat_' + hashlib.md5(group_id.encode('utf-8')).hexdigest()}
    expected_text = {'incoming': '@~ ' + token + '_IN', 'outgoing': token + '_OUT'}
    found = {direction: [] for direction in expected_text}
    for path in messages:
        message_db, captures[path.name] = _open_database(path, key)
        with closing(message_db) as db:
            tables = {row['name'] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
            matches = tables & expected_tables
            if len(matches) > 1:
                raise RuntimeError('Ambiguous exact group message tables')
            if not matches:
                continue
            table = matches.pop()
            rows = db.execute(f'SELECT m.local_id,m.server_id,m.create_time,m.sort_seq,m.real_sender_id,'
                f'CAST(m.message_content AS BLOB) AS message_content,'
                f'CAST(m.compress_content AS BLOB) AS compress_content,n.user_name AS sender_id FROM "{table}" m '
                'LEFT JOIN Name2Id n ON m.real_sender_id=n.rowid WHERE m.local_type=1')
            for row in rows:
                content = _decode_content(row['message_content'], row['compress_content'])
                sender = row['sender_id']
                if sender is not None and content.startswith(sender + ':\n'):
                    content = content[len(sender) + 2:]
                for direction, expected in expected_text.items():
                    if content != expected:
                        continue
                    if not sender:
                        raise RuntimeError('Synthetic nonce has no Name2Id sender mapping')
                    found[direction].append({'direction': direction, 'content': expected,
                        'sender_id': sender, 'real_sender_id': row['real_sender_id'],
                        'local_id': row['local_id'], 'server_id': row['server_id'],
                        'create_time': row['create_time'], 'sort_seq': row['sort_seq'],
                        'database': path.name, 'table': table})
    if any(len(samples) != 1 for samples in found.values()):
        raise RuntimeError('Expected exactly one incoming and one outgoing synthetic nonce')
    incoming, outgoing = found['incoming'][0], found['outgoing'][0]
    if outgoing['sender_id'] != self_id or incoming['sender_id'] == self_id:
        raise RuntimeError('Nonce direction disagrees with the account folder identity')
    if _message_files(db_root) != messages:
        raise RuntimeError('Message database inventory changed during capture')
    return {'group_id': group_id, 'self_id': self_id, 'samples': [incoming, outgoing],
            'outgoing_sender_matches_account': True, 'captures': captures,
            'identity_scope': 'Controlled nonce sender matches folder identity; not proof of current UI login',
            'elapsed_seconds': round(time.perf_counter() - started, 3)}
