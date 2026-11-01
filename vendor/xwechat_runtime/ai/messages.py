"""Exact-source identity/cursor helpers; no original snapshot/export imports."""


def message_identity(server_id, anchor, timestamp, local_type=0):
    """各读取入口共用消息身份；没有服务端编号时保留数据库定位与时间。"""
    try:
        server_id = int(server_id or 0)
    except (TypeError, ValueError):
        server_id = 0
    identity = f's:{server_id}' if server_id else (
        f'l:{anchor}:{timestamp}' if len(anchor.split(':')) == 3 else anchor)
    # 微信可把原记录原地改成系统撤回提示，仍使用原 server ID；归档原文是另一条消息。
    return f'system:{identity}' if int(local_type or 0) == 10000 else identity


def filter_after(messages, cursor):
    timestamp = int(cursor.get("time", 0))
    ids = set(cursor.get("ids", []))
    return [m for m in messages if m["time"] > timestamp or (m["time"] == timestamp and m["identity"] not in ids)]


def advance_cursor(messages, previous=None):
    previous = previous or {"time": 0, "ids": []}
    if not messages:
        return previous
    timestamp = max(previous["time"], max(m["time"] for m in messages))
    ids = set(previous["ids"]) if timestamp == previous["time"] else set()
    ids.update(m["identity"] for m in messages if m["time"] == timestamp)
    return {"time": timestamp, "ids": sorted(ids)}
