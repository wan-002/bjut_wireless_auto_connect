from __future__ import annotations

import json
import random
import re
import ssl
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime
from typing import Any


# =============================================================================
# 用户配置区：请直接修改这些参数
# =============================================================================

# 校园网账号和密码填在引号内
USERNAME = ""
PASSWORD = ""

# 一轮断网期间最多执行多少次重新认证；全部失败后脚本退出。
MAX_RECONNECT_ATTEMPTS = 5

# 两次重新认证之间的等待时间，单位：秒。
RECONNECT_INTERVAL_SECONDS = 10

# 联网正常时，每隔多少秒检查一次互联网连通性。
CONNECTIVITY_CHECK_INTERVAL_SECONDS = 30

# 每个连通性检测请求的超时时间，单位：秒。
CONNECTIVITY_CHECK_TIMEOUT_SECONDS = 5

# 登录请求的超时时间，单位：秒。
LOGIN_TIMEOUT_SECONDS = 10

# 提交登录请求后等待网络生效的时间，单位：秒。
LOGIN_SETTLE_SECONDS = 2

# 任意一个地址访问成功即视为互联网正常。如学校屏蔽了某个站点，可替换它。
CONNECTIVITY_CHECK_URLS = (
    "https://www.baidu.com/favicon.ico",
    "https://www.qq.com/favicon.ico",
)

# 校园网认证地址。通常不需要修改。
LOGIN_URL = "https://wlgn.bjut.edu.cn/drcom/login"
LOGIN_REFERER = "https://wlgn.bjut.edu.cn/"


VERIFY_LOGIN_TLS_CERTIFICATE = True

# =============================================================================
# 用户配置区结束
# =============================================================================


USER_AGENT = (
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/120.0 Safari/537.36"
)


class LoginError(Exception):
    """登录请求未能完成。"""


def log(message: str, *, error: bool = False) -> None:
    """打印带时间的日志。"""
    stream = sys.stderr if error else sys.stdout
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    print(f"[{timestamp}] {message}", file=stream, flush=True)


def validate_config() -> None:
    """在发送任何网络请求之前检查用户配置。"""
    errors: list[str] = []
    if not USERNAME.strip():
        errors.append("请先在脚本顶部填写 USERNAME")
    if not PASSWORD:
        errors.append("请先在脚本顶部填写 PASSWORD")
    if not isinstance(MAX_RECONNECT_ATTEMPTS, int) or MAX_RECONNECT_ATTEMPTS < 1:
        errors.append("MAX_RECONNECT_ATTEMPTS 必须是大于等于 1 的整数")
    if RECONNECT_INTERVAL_SECONDS < 0:
        errors.append("RECONNECT_INTERVAL_SECONDS 不能小于 0")
    if CONNECTIVITY_CHECK_INTERVAL_SECONDS <= 0:
        errors.append("CONNECTIVITY_CHECK_INTERVAL_SECONDS 必须大于 0")
    if CONNECTIVITY_CHECK_TIMEOUT_SECONDS <= 0:
        errors.append("CONNECTIVITY_CHECK_TIMEOUT_SECONDS 必须大于 0")
    if LOGIN_TIMEOUT_SECONDS <= 0:
        errors.append("LOGIN_TIMEOUT_SECONDS 必须大于 0")
    if LOGIN_SETTLE_SECONDS < 0:
        errors.append("LOGIN_SETTLE_SECONDS 不能小于 0")
    if not CONNECTIVITY_CHECK_URLS:
        errors.append("CONNECTIVITY_CHECK_URLS 至少需要包含一个 HTTPS 地址")

    for url in CONNECTIVITY_CHECK_URLS:
        if urllib.parse.urlsplit(url).scheme.lower() != "https":
            errors.append(f"连通性检测地址必须使用 HTTPS：{url}")

    if errors:
        raise ValueError("；".join(errors))


def internet_is_available() -> bool:
    for url in CONNECTIVITY_CHECK_URLS:
        request = urllib.request.Request(
            url,
            headers={
                "Accept": "*/*",
                "Cache-Control": "no-cache",
                "User-Agent": USER_AGENT,
            },
            method="GET",
        )
        expected_host = (urllib.parse.urlsplit(url).hostname or "").lower()
        try:
            with urllib.request.urlopen(
                request, timeout=CONNECTIVITY_CHECK_TIMEOUT_SECONDS
            ) as reply:
                # 只读取一个字节，避免周期检测产生不必要的流量。
                reply.read(1)
                final_host = (
                    urllib.parse.urlsplit(reply.geturl()).hostname or ""
                ).lower()
                if 200 <= reply.status < 400 and final_host == expected_host:
                    return True
        except (urllib.error.URLError, TimeoutError, OSError, ValueError):
            continue
    return False


def build_login_request() -> urllib.request.Request:
    params = [
        ("callback", "dr1003"),
        ("DDDDD", USERNAME),
        ("upass", PASSWORD),
        ("0MKKey", "123456"),
        ("R1", "0"),
        ("R2", ""),
        ("R3", "0"),
        ("R6", "0"),
        ("para", "00"),
        ("v6ip", ""),
        ("terminal_type", "1"),
        ("lang", "zh-cn"),
        ("jsVersion", "4.1"),
        ("v", str(random.randint(1000, 9999))),
        ("lang", "zh"),
    ]
    query = urllib.parse.urlencode(params)
    separator = "&" if urllib.parse.urlsplit(LOGIN_URL).query else "?"
    return urllib.request.Request(
        f"{LOGIN_URL}{separator}{query}",
        headers={
            "Accept": "*/*",
            "Accept-Language": "zh-CN,zh;q=0.9",
            "Referer": LOGIN_REFERER,
            "User-Agent": USER_AGENT,
        },
        method="GET",
    )


def decode_body(data: bytes) -> str:
    for encoding in ("utf-8-sig", "gb18030"):
        try:
            return data.decode(encoding)
        except UnicodeDecodeError:
            pass
    return data.decode("utf-8", errors="replace")


def parse_jsonp(text: str) -> dict[str, Any] | None:
    stripped = text.strip()
    match = re.fullmatch(r"[A-Za-z_$][\w$]*\s*\((.*)\)\s*;?", stripped, re.DOTALL)
    candidate = match.group(1) if match else stripped
    try:
        value = json.loads(candidate)
    except json.JSONDecodeError:
        return None
    return value if isinstance(value, dict) else None


def interpret_login_response(text: str) -> tuple[bool, str]:
    """返回 (认证是否成功, 门户消息)。"""
    payload = parse_jsonp(text)
    if payload is not None:
        result = payload.get("result")
        message = str(
            payload.get("msg")
            or payload.get("message")
            or payload.get("ret_msg")
            or "认证服务器未返回说明"
        )
        return result in (1, "1", True), message

    compact = " ".join(text.split())
    success = any(
        marker in compact.lower()
        for marker in ("认证成功", "登录成功", "login_ok", "login success")
    )
    return success, compact[:300] or "认证服务器返回空响应"


def login_once() -> tuple[bool, str]:
    request = build_login_request()
    context = None
    if not VERIFY_LOGIN_TLS_CERTIFICATE:
        context = ssl._create_unverified_context()

    try:
        with urllib.request.urlopen(
            request, timeout=LOGIN_TIMEOUT_SECONDS, context=context
        ) as reply:
            body = decode_body(reply.read())
    except urllib.error.HTTPError as exc:
        detail = decode_body(exc.read())[:300]
        raise LoginError(f"HTTP {exc.code}：{detail or exc.reason}") from exc
    except (urllib.error.URLError, TimeoutError, OSError) as exc:
        raise LoginError(str(exc)) from exc
    return interpret_login_response(body)


def restore_connectivity() -> bool:
    """执行一轮重连；超过配置的最大尝试次数后返回 False。"""
    for attempt in range(1, MAX_RECONNECT_ATTEMPTS + 1):
        # 断网可能只是短暂抖动，发认证请求前再确认一次。
        if internet_is_available():
            log("互联网连接已自行恢复，无需重新认证。")
            return True

        log(f"开始第 {attempt}/{MAX_RECONNECT_ATTEMPTS} 次重新认证……")
        try:
            accepted, message = login_once()
            if accepted:
                log(f"认证服务器已接受请求：{message}")
            else:
                log(f"认证服务器拒绝请求：{message}", error=True)
        except LoginError as exc:
            log(f"认证请求失败：{exc}", error=True)

        if LOGIN_SETTLE_SECONDS:
            time.sleep(LOGIN_SETTLE_SECONDS)
        if internet_is_available():
            log("互联网连接已恢复。")
            return True

        if attempt < MAX_RECONNECT_ATTEMPTS:
            log(f"连接仍未恢复，{RECONNECT_INTERVAL_SECONDS} 秒后重试。")
            time.sleep(RECONNECT_INTERVAL_SECONDS)

    return False


def main() -> int:
    try:
        validate_config()
    except (TypeError, ValueError) as exc:
        log(f"配置错误：{exc}", error=True)
        return 2

    log(
        "开始监测互联网连通性"
        f"（每 {CONNECTIVITY_CHECK_INTERVAL_SECONDS} 秒检查一次）。"
    )

    try:
        while True:
            if internet_is_available():
                time.sleep(CONNECTIVITY_CHECK_INTERVAL_SECONDS)
                continue

            log("检测到互联网不可用，进入重新认证流程。", error=True)
            if not restore_connectivity():
                log(
                    f"连续 {MAX_RECONNECT_ATTEMPTS} 次重新认证后仍无法联网，进程退出。",
                    error=True,
                )
                return 1
            time.sleep(CONNECTIVITY_CHECK_INTERVAL_SECONDS)
    except KeyboardInterrupt:
        log("收到中断信号，进程退出。")
        return 0


if __name__ == "__main__":
    raise SystemExit(main())
