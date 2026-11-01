"""Cloud-only composition of the reused automatic-reply services.

The stdlib entry verifies the host before importing this module. Keys stay in
the owned worker; status contains metadata rather than credentials or messages.
"""
import asyncio
from dataclasses import replace
import json
from pathlib import Path, PureWindowsPath
import re
from types import SimpleNamespace

import psutil

from cloud_bot import ACCOUNT, DATA_ROOT, GROUP_ID, GROUP_NAME, SELF_ID, MAAS_BASE
from cloud_db_key import recover_verified_key
from cloud_db_reader import database_paths
from cloud_probe import read_windows
from cloud_source import CloudSource
from vendor.xwechat_runtime.ai.auto_reply import ATTEMPT, AutoReplyBody, AutoReplyService
from vendor.xwechat_runtime.ai.messages import message_identity
from vendor.xwechat_runtime.ai.providers import ModelService, model_base_url, validate_url
from vendor.xwechat_runtime.ai.storage import AIStore
from vendor.xwechat_runtime.snapshot_events import notify_snapshot_change
from vendor.xwechat_runtime.wechat_ui_bridge import ControlledSendError, WeChatBridge, WeChatWindowBinding

PROFILE_ID = 'cloud-bot'
DB_CONFIRM_SECONDS = 15.0
MAAS_MODEL = 'deepseek-v4.1-flash-1017'
MAAS_DOCUMENTATION = 'https://help.aliyun.com/en/model-studio/deepseek-api'
PLAIN_REPLY_INSTRUCTION = '\n本次仅输出回复正文，不要 JSON 封装、字段名或 Markdown 代码围栏。'


class CloudRuntimeError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def text_trigger(message, mention_name):
    # shortcut: text-name matching cannot prove native @ identity; use member IDs if required.
    mention = re.compile('@' + re.escape(mention_name) + r'(?=\s|$)')
    text = message['text']
    return bool(mention.search(text) and mention.sub('', text).strip())


def configured_maas_model(profile):
    return (profile['protocol'] == 'openai' and profile['model'] == MAAS_MODEL
            and model_base_url(profile['base_url']) == MAAS_BASE)


class CloudModelService(ModelService):
    def __init__(self, store, registry):
        super().__init__(store)
        self.registry = registry

    @staticmethod
    def client(profile):
        client = ModelService.client(profile)
        if configured_maas_model(profile):
            # Preserve the original verified Bailian Chat Completions settings.
            client.extra_body = {**(client.extra_body or {}), 'enable_thinking': False}
            client.use_responses_api = False
        return client

    async def invoke(self, profile, prompt, schema=None, images=None, account='', *, system_prompt=None):
        if schema is not AutoReplyBody or not isinstance(system_prompt, str):
            raise TypeError('Cloud replies require AutoReplyBody and an explicit reply system prompt')
        # shortcut: core preflight retains a conservative schema reserve for this shorter text request.
        with self.registry.operation('model', 180):
            body = await super().invoke(profile, prompt, schema=None, images=images, account=account,
                                        system_prompt=system_prompt + PLAIN_REPLY_INSTRUCTION)
        return AutoReplyBody.model_validate({'body': body}, strict=True).model_dump()


class CloudSender:
    def __init__(self, bridge, source, registry):
        self.bridge, self.source, self.registry = bridge, source, registry

    def validate_window_binding(self, binding):
        with self.registry.operation('window_check', 20):
            self.bridge.validate_window_binding(binding)

    async def send_controlled_text(self, **request):
        if (request['account'], request['session_id'], request['target_name']) != (ACCOUNT, GROUP_ID, GROUP_NAME):
            raise CloudRuntimeError('CLOUD_SEND_TARGET_CHANGED')
        original_check = request['check_before_send']
        baseline = None

        async def before_send():
            nonlocal baseline
            await original_check()
            view = await self.source.read(ACCOUNT, GROUP_ID, fresh=True, baseline=True)
            baseline = view['latest_cursor']

        with self.registry.operation('controlled_send', 60):
            receipt = await self.bridge.send_controlled_text(**{**request, 'check_before_send': before_send})
            # A UI receipt alone cannot prove sender identity on this client.
            try:
                async with asyncio.timeout(DB_CONFIRM_SECONDS):
                    while True:
                        view = await self.source.read(ACCOUNT, GROUP_ID, cursor=baseline, fresh=True)
                        matches = [msg for msg in view['messages'] if msg['sender_id'] == SELF_ID
                                   and msg['media']['type'] == 1 and msg['text'] == request['content']
                                   # A late server ID must not turn a known local row into this send.
                                   and message_identity(0, msg['anchor'], msg['time'], 1) not in baseline['ids']]
                        if len(matches) > 1:
                            raise CloudRuntimeError('CLOUD_OUTGOING_AMBIGUOUS')
                        if matches and type(matches[0]['server_id']) is int and matches[0]['server_id'] > 0:
                            message = matches[0]
                            outgoing = {key: message[key] for key in
                                        ('identity', 'server_id', 'time', 'database', 'table', 'local_id')}
                            self.registry.update(last_outgoing=outgoing)
                            return replace(receipt, evidence={**receipt.evidence, 'database_outgoing': outgoing})
                        await asyncio.sleep(.5)
            except Exception as exc:
                raise ControlledSendError('Own database message was not uniquely confirmed; do not resend',
                    code='WECHAT_SEND_UNCONFIRMED', status_code=504, stage='database_confirmation',
                    submission_intended=True, submission_attempted=True) from exc


async def create_service(config, runtime_root, registry, source, bridge):
    validate_url(config['base_url'])
    store = AIStore(Path(runtime_root) / 'ai')
    store.recover_interrupted_usage()
    models = CloudModelService(store, registry)
    service = AutoReplyService(SimpleNamespace(store=store, models=models), source=source,
        sender=CloudSender(bridge, source, registry),
        trigger_filter=lambda message: text_trigger(message, config['mention_name']))
    service.recover()
    profile = {'id': PROFILE_ID, 'name': 'Cloud bot', 'provider': 'qwen', 'protocol': 'openai',
               'base_url': config['base_url'], 'api_key': config['api_key'], 'model': config['model'],
               'vision': False, 'model_overrides': {}}
    if configured_maas_model(profile):
        # This model supports JSON Object, not native JSON Schema (official table).
        profile['model_overrides'] = {'structured_output': True, 'documentation_url': MAAS_DOCUMENTATION}
    previous = store.get('profile', PROFILE_ID)
    revision = previous['revision'] if previous else 1
    if previous and any(previous.get(key) != value for key, value in profile.items()):
        revision += 1
    store.put('profile', {**profile, 'revision': revision}, id=PROFILE_ID)
    await service.configure(ACCOUNT, {'profile_id': PROFILE_ID, 'model_id': config['model'],
        'system_prompt': config['system_prompt'], 'sessions': [{'session_id': GROUP_ID,
            'target_name': GROUP_NAME, 'enabled': True, 'group_trigger': 'all'}]})
    publish_status(service, registry)
    return service


def publish_status(service, registry):
    status = service.status(ACCOUNT)
    with service.store.connection() as db:
        rows = db.execute("SELECT id,json_extract(body,'$.status') AS status,"
            "json_extract(body,'$.run_id') AS run_id,"
            "json_extract(body,'$.error.code') AS error_code,"
            "json_extract(body,'$.evidence.database_outgoing') AS outgoing "
            "FROM records WHERE kind=? AND account=? ORDER BY updated", (ATTEMPT, ACCOUNT)).fetchall()
    state = status['state']
    session = next((item for item in status['sessions'] if item['session_id'] == GROUP_ID), None)
    if state == 'running' and session and session['status'] != 'running':
        state = session['status']
    if any(row['status'] == 'needs_review' for row in rows):
        state = 'needs_review'
    failed = next((row for row in reversed(rows)
                   if row['status'] == 'failed' and row['run_id'] == service.run_id), None)
    # A failed batch is an actual visible stop, not a healthy waiting screen.
    if state == 'running' and failed:
        state = 'failed'
    error = status['error'] or (session['error'] if session else None)
    last = rows[-1] if rows else None
    last_error = last['error_code'] if last and (last['run_id'] == service.run_id or state != 'running') else None
    outgoing = next((row['outgoing'] for row in reversed(rows) if row['outgoing']), None)
    values = dict(state=state, account=ACCOUNT, group=GROUP_NAME, model=service.config(ACCOUNT)['model_id'],
                  completed=sum(row['status'] == 'completed' for row in rows),
                  needs_review=sum(row['status'] == 'needs_review' for row in rows),
                  last_attempt_id=last['id'] if last else None,
                  error_code=error['code'] if error else failed['error_code'] if failed else last_error,
                  last_outgoing=json.loads(outgoing) if outgoing else None)
    registry.update(**values)
    return values


async def confirm_start(service, registry, mention_name):
    publish_status(service, registry)
    with service.store.connection() as db:
        pending = db.execute("SELECT id FROM records WHERE kind=? AND account=? "
            "AND json_extract(body,'$.status')='needs_review' ORDER BY updated", (ATTEMPT, ACCOUNT)).fetchall()
    for row in pending:
        print(f"Uncertain attempt {row['id']}: check WeChat manually. No automatic resend.", flush=True)
        conclusion = await asyncio.to_thread(input, 'Review: sent / not_sent / uncertain (keep stopped): ')
        if conclusion not in ('sent', 'not_sent'):
            return False
        await service.review(ACCOUNT, row['id'], conclusion)
        publish_status(service, registry)
    print(f'Account: {ACCOUNT}; self: {SELF_ID}\nGroup: {GROUP_NAME} ({GROUP_ID})\n'
          f"Model: {service.config(ACCOUNT)['model_id']}\n"
          f'Mention: @{mention_name} (exact name; whitespace before the question)\n'
          'Confirm this account is logged into the selected cloud WeChat window. '
          'Existing messages are skipped; only new nonempty questions mentioning this name trigger.', flush=True)
    if await asyncio.to_thread(input, 'Type START to enable; any other input keeps replies off: ') != 'START':
        registry.update(state='off')
        return False
    await service.resume(ACCOUNT, GROUP_ID, confirmed=True)
    return True


async def notify_changes():
    while True:
        await asyncio.sleep(1)
        notify_snapshot_change(ACCOUNT)


async def serve(service, binding, registry):
    ticker = None
    try:
        await service.start(ACCOUNT, binding, confirmed=True)
        status = publish_status(service, registry)
        if status['state'] != 'running':
            raise CloudRuntimeError(status['error_code'] or 'CLOUD_RUNTIME_NOT_RUNNING')
        print('Bot running. Send a new question with the configured @name in the target group.', flush=True)
        ticker = asyncio.create_task(notify_changes())
        while True:
            await asyncio.sleep(.25)
            if ticker.done():
                await ticker
                raise CloudRuntimeError('CLOUD_NOTIFIER_EXIT')
            status = publish_status(service, registry)
            if status['state'] != 'running':
                raise CloudRuntimeError(status['error_code'] or 'CLOUD_RUNTIME_NOT_RUNNING')
    except Exception as exc:
        if registry.values['state'] not in ('needs_review', 'paused', 'failed'):
            registry.update(state='failed', error_code=getattr(exc, 'code', type(exc).__name__))
        raise
    finally:
        if ticker is not None:
            ticker.cancel()
            await asyncio.gather(ticker, return_exceptions=True)
        await service.stop()


async def run_worker(config, runtime_root, registry):
    with registry.operation('native_discovery', 20):
        native = await asyncio.to_thread(read_windows)
        window = native['window']
        expected = PureWindowsPath(r'C:\Program Files\Tencent\Weixin\Weixin.exe')
        if (PureWindowsPath(window['image_path']) != expected or window['version'] != '4.2.0.12'
                or window['minimized']):
            raise CloudRuntimeError('CLOUD_WECHAT_WINDOW_CHANGED')
        binding = WeChatWindowBinding(window['pid'], psutil.Process(window['pid']).create_time(), window['hwnd'])
    with registry.operation('key_recovery', 150):
        paths = database_paths(DATA_ROOT)
        key = await asyncio.to_thread(recover_verified_key, window, paths)
    source = CloudSource(DATA_ROOT, key, account=ACCOUNT, self_id=SELF_ID, group_id=GROUP_ID,
                         target_group=GROUP_NAME, activity=registry.operation)
    del key
    service = await create_service(config, runtime_root, registry, source, WeChatBridge())
    if await confirm_start(service, registry, config['mention_name']):
        await serve(service, binding, registry)
