"""Fixed-account runtime reads from authenticated, in-memory cloud snapshots."""
import asyncio
from contextlib import closing
import hashlib
from pathlib import Path
import threading

import cloud_db_reader as reader
from vendor.xwechat_runtime.ai.messages import advance_cursor, filter_after, message_identity


class CloudSourceError(RuntimeError):
    def __init__(self, stage, detail):
        super().__init__(detail)
        self.code = 'AUTO_REPLY_SOURCE_' + stage.upper()
        self.detail = detail


class CloudSource:
    def __init__(self, data_root: Path, key: bytes, *, account: str, self_id: str,
                 group_id: str, target_group: str, activity):
        if not isinstance(key, bytes) or len(key) != reader.KEY_SIZE:
            raise ValueError('CloudSource requires a verified 32-byte key')
        if any(not isinstance(value, str) or not value or value != value.strip()
               for value in (account, self_id, group_id, target_group)):
            raise ValueError('Explicit account, self identity and exact group are required')
        self.data_root, self._key = Path(data_root), key
        self.account, self.self_id = account, self_id
        self.group_id, self.target_group, self.activity = group_id, target_group, activity
        self._binding = None
        self._lock = asyncio.Lock()
        self._capture_lock = threading.Lock()

    def _account(self, account):
        if account != self.account:
            raise CloudSourceError('changed', 'Cloud source account differs from the configured account')

    def _paths(self):
        paths = reader.database_paths(self.data_root)
        root = paths['db_root']
        if root.parent.name != self.account:
            raise CloudSourceError('changed', 'Cloud source account directory changed')
        directories = (self.data_root, root.parent, root,
                       root / 'session', root / 'contact', root / 'message')
        identities = []
        for path in directories:
            info = path.stat()
            identities.append((str(path.resolve()), info.st_dev, info.st_ino))
        for name in ('session', 'contact', 'message'):
            directory = root / name
            if directory.resolve() != root.resolve() / name:
                raise CloudSourceError('changed', 'Linked cloud source directories are not accepted')
        return paths, {'account': self.account, 'directories': identities}

    def verify_binding(self, account, binding):
        self._account(account)
        if self._binding is None or binding != self._binding:
            raise CloudSourceError('changed', 'Cloud source binding is missing or changed')
        _, current = self._paths()
        if current != binding:
            raise CloudSourceError('changed', 'Cloud source directory identity changed')

    async def verify(self, account, binding):
        self.verify_binding(account, binding)

    async def start(self, account):
        self._account(account)
        async with self._lock:
            view = await asyncio.to_thread(self._collect, None, True, self._binding)
            self._binding = view['binding']

    async def read(self, account, session_id, *, cursor=None, fresh=False, baseline=False,
                   binding=None, needs_mentions=False):
        self._account(account)
        if session_id != self.group_id:
            raise CloudSourceError('conversation', 'Cloud source only reads its configured exact group')
        if needs_mentions:
            raise CloudSourceError('mentions', 'Text @~ does not provide native atUsernames identity')
        if not baseline and (not isinstance(cursor, dict) or set(cursor) != {'time', 'ids'}
                or type(cursor['time']) is not int or cursor['time'] < 0
                or not isinstance(cursor['ids'], list)
                or any(not isinstance(value, str) for value in cursor['ids'])):
            raise CloudSourceError('read', 'An explicit valid incremental cursor is required')
        if self._binding is None:
            raise CloudSourceError('unavailable', 'Cloud source must be started before reading')
        async with self._lock:
            # Every read captures now; fresh never aliases an older cached snapshot.
            return await asyncio.to_thread(self._collect, cursor, baseline,
                                           self._binding if binding is None else binding)

    @staticmethod
    def _message(row, path, table):
        sender = row['sender_id']
        content = None
        if row['local_type'] == 1:
            if not isinstance(sender, str) or not sender:
                raise CloudSourceError('identity', 'Text message has no Name2Id sender mapping')
            content = reader._decode_content(row['message_content'], row['compress_content'])
            if content.startswith(sender + ':\n'):
                content = content[len(sender) + 2:]
        anchor = f"{path.stem}:{table}:{row['local_id']}"
        return {'identity': message_identity(row['server_id'], anchor, row['create_time'], row['local_type']),
                'time': row['create_time'], 'sender_id': sender, 'sender': sender, 'text': content,
                'media': {'type': row['local_type']}, 'anchor': anchor,
                'server_id': row['server_id'], 'local_id': row['local_id'],
                'database': path.name, 'table': table}

    @staticmethod
    def _unique(messages):
        unique = {}
        for message in messages:
            previous = unique.get(message['identity'])
            if previous is not None and any(previous[key] != message[key]
                    for key in ('time', 'sender_id', 'text', 'media')):
                raise CloudSourceError('identity', 'Conflicting records share one message identity')
            unique[message['identity']] = message
        return sorted(unique.values(), key=lambda message: (message['time'], message['identity']))

    def _collect(self, cursor, baseline, binding):
        # Cancellation cannot stop to_thread; retain physical serialization until it exits.
        with self._capture_lock, self.activity('source_read', 45):
            paths, current = self._paths()
            if (self._binding is not None and current != self._binding
                    or binding is not None and current != binding):
                raise CloudSourceError('changed', 'Cloud source binding changed before capture')
            root = paths['db_root']
            messages = reader._message_files(root)
            files = [paths['session'], paths['contact'], *messages]
            size = sum(state[2] for path in files for suffix in ('', '-wal', '-shm', '-journal')
                       if (state := reader._file_state(Path(str(path) + suffix))) is not None)
            if size > reader.MAX_CAPTURE_BYTES:
                raise CloudSourceError('read', 'Snapshot capacity exceeds the 64 MiB limit')
            with closing(reader._open_database(paths['session'], self._key)[0]):
                pass
            with closing(reader._open_database(paths['contact'], self._key)[0]) as db:
                groups = db.execute("SELECT username FROM contact WHERE username LIKE '%@chatroom' AND "
                    "CASE WHEN remark IS NOT NULL AND remark <> '' THEN remark ELSE nick_name END = ?",
                    (self.target_group,)).fetchall()
            if len(groups) != 1 or groups[0]['username'] != self.group_id:
                raise CloudSourceError('conversation', 'Exact cloud target group identity changed or is ambiguous')
            expected = hashlib.md5(self.group_id.encode('utf-8')).hexdigest()
            expected_tables = {'Msg_' + expected, 'Chat_' + expected}
            observed, context, latest = [], [], []
            matched = False
            for path in messages:
                with closing(reader._open_database(path, self._key)[0]) as db:
                    tables = {row['name'] for row in db.execute("SELECT name FROM sqlite_master WHERE type='table'")}
                    matches = tables & expected_tables
                    if len(matches) > 1:
                        raise CloudSourceError('conversation', 'Ambiguous exact cloud group tables')
                    if not matches:
                        continue
                    matched = True
                    table = matches.pop()
                    if db.execute('SELECT COUNT(*) FROM Name2Id WHERE user_name=?',
                                  (self.self_id,)).fetchone()[0] != 1:
                        raise CloudSourceError('identity', 'Cloud account has no unique Name2Id self mapping')
                    latest.extend({'identity': message_identity(row['server_id'],
                        f"{path.stem}:{table}:{row['local_id']}", row['create_time'], row['local_type']),
                        'time': row['create_time']} for row in db.execute(
                            f'SELECT local_id,server_id,create_time,local_type FROM "{table}" '
                            f'WHERE create_time=(SELECT MAX(create_time) FROM "{table}")'))
                    select = (f'SELECT m.local_id,m.server_id,m.local_type,m.create_time,m.sort_seq,'
                        'CAST(m.message_content AS BLOB) AS message_content,'
                        'CAST(m.compress_content AS BLOB) AS compress_content,n.user_name AS sender_id '
                        f'FROM "{table}" m LEFT JOIN Name2Id n ON m.real_sender_id=n.rowid ')
                    if not baseline:
                        observed.extend(self._message(row, path, table) for row in db.execute(
                            select + 'WHERE m.create_time>=? ORDER BY m.create_time,m.sort_seq,m.local_id',
                            (cursor['time'],)))
                    context.extend(self._message(row, path, table) for row in db.execute(select +
                        'WHERE m.local_type=1 ORDER BY m.create_time DESC,m.sort_seq DESC,m.local_id DESC LIMIT 10'))
            if not matched:
                raise CloudSourceError('conversation', 'No exact cloud target group message table')
            _, after = self._paths()
            if after != current or reader._message_files(root) != messages:
                raise CloudSourceError('changed', 'Cloud source directory or shard inventory changed during capture')
            latest_cursor = advance_cursor(latest)
            observed = [] if baseline else filter_after(self._unique(observed), cursor)
            return {'binding': current, 'self_id': self.self_id, 'messages': observed,
                    'cursor': latest_cursor if baseline else advance_cursor(observed, cursor),
                    'latest_cursor': latest_cursor, 'context': self._unique(context)[-10:]}
