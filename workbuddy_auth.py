"""Credential boundary: fixed errors, local decryption, portable minimal exports."""
import base64
import contextlib
import json
import math
import os
from pathlib import Path
import re
import subprocess
import tempfile
import time


class AuthError(ValueError):
    pass


SENSITIVE = set()


def remember(value):
    if isinstance(value, str) and value:
        SENSITIVE.add(value)


def redact(value):
    text = str(value)
    for secret in sorted(SENSITIVE, key=len, reverse=True):
        if len(secret) >= 4:
            text = text.replace(secret, "[hidden]")
            text = text.replace(json.dumps(secret, ensure_ascii=True)[1:-1], "[hidden]")
    text = re.sub(r"(?<!\d)1[3-9]\d{9}(?!\d)", "[phone hidden]", text)
    text = re.sub(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[token hidden]", text)
    return text


def epoch_seconds(value):
    try:
        if isinstance(value, bool):
            raise ValueError()
        number = float(value or 0)
        if not math.isfinite(number) or number < 0:
            raise ValueError()
        return int(number / 1000 if number > 100_000_000_000 else number)
    except (TypeError, ValueError, OverflowError):
        raise AuthError("凭证过期时间无效") from None


def runtime_path():
    override = os.environ.get("WORKBUDDY_EXE")
    if override:
        candidates = [Path(override).expanduser()]
    elif os.name == "nt":
        candidates = [Path(os.environ.get("LOCALAPPDATA", "")) / "Programs/WorkBuddy/WorkBuddy.exe"]
        candidates += [Path(os.environ[k]) / "WorkBuddy/WorkBuddy.exe"
                       for k in ("ProgramFiles", "ProgramFiles(x86)") if k in os.environ]
    else:
        candidates = [Path("/Applications/WorkBuddy.app/Contents/MacOS/WorkBuddy"),
                      Path.home() / "Applications/WorkBuddy.app/Contents/MacOS/WorkBuddy"]
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate.resolve())
    raise AuthError("加密凭证需要匹配的 WorkBuddy 客户端；请在本机导出，云端不能直接解密。可用 WORKBUDDY_EXE 指定客户端")


def token_value(value, required=False):
    if value in (None, "") and not required:
        return ""
    if isinstance(value, dict):
        if (set(value) != {"$wbEncrypted", "envelope"} or
                type(value.get("$wbEncrypted")) is not int or value["$wbEncrypted"] != 1 or
                not isinstance(value.get("envelope"), str) or len(value["envelope"]) > 60_000):
            raise AuthError("不支持的 WorkBuddy 加密信封")
        helper = Path(__file__).with_name("workbuddy_decrypt.js").read_text(encoding="utf-8")
        env = {k: v for k, v in os.environ.items()
               if not k.upper().startswith(("NODE_", "ELECTRON_", "WORKBUDDY_", "GH_", "GITHUB_", "BARK_"))}
        env["ELECTRON_RUN_AS_NODE"] = "1"
        try:
            result = subprocess.run([runtime_path(), "-e", helper],
                                    input=json.dumps({"version": 1, "operation": "decrypt", "value": value}).encode(),
                                    capture_output=True, timeout=15, env=env, shell=False,
                                    creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            reply = json.loads(result.stdout)
            if result.returncode or not isinstance(reply, dict) or reply.get("ok") is not True:
                raise AuthError("加密凭证解密失败：客户端版本、密钥或信封不匹配；请重新登录后导出")
            value = reply.get("accessToken")
        except AuthError:
            raise
        except (OSError, subprocess.SubprocessError, ValueError):
            raise AuthError("加密凭证解密失败：需要匹配的本机客户端和完整的 suite 1 信封") from None
    if not isinstance(value, str) or not re.fullmatch(r"[A-Za-z0-9._~+/=-]{1,32768}", value):
        raise AuthError("凭证 token 格式无效；不允许把信封对象作为 HTTP 令牌发送")
    remember(value)
    return value


def normalize_auth(data):
    if not isinstance(data, dict):
        raise AuthError("凭证必须为 JSON 对象")
    auth = data.get("auth", data)
    account = data.get("account", data)
    if not isinstance(auth, dict) or not isinstance(account, dict):
        raise AuthError("凭证 auth/account 格式无效")
    for source in (auth, account):
        for key in ("nickname", "phone", "phoneNumber", "uid", "sessionState", "uin"):
            remember(source.get(key))
    domain = auth.get("domain") or "codebuddy.cn"
    if domain not in ("codebuddy.cn", "www.codebuddy.cn", "workbuddy.cn", "www.workbuddy.cn",
                       "workbuddy.ai", "www.workbuddy.ai"):
        raise AuthError("凭证 domain 不在支持的服务域名范围")
    minimal_account = {}
    for key in ("uid", "enterpriseId"):
        value = account.get(key) or ""
        if not isinstance(value, str) or (value and not re.fullmatch(r"[A-Za-z0-9._:@-]{1,256}", value)):
            raise AuthError("凭证账号标识格式无效")
        minimal_account[key] = value
    return {"auth": {"accessToken": token_value(auth.get("accessToken"), required=True),
                     "refreshToken": token_value(auth.get("refreshToken")),
                     "expiresAt": epoch_seconds(auth.get("expiresAt")), "domain": domain},
            "account": minimal_account, "disabled": bool(data.get("disabled", False))}


def read_auth(path):
    try:
        with open(path, encoding="utf-8-sig") as stream:
            return normalize_auth(json.load(stream))
    except (OSError, UnicodeError, json.JSONDecodeError):
        raise AuthError("无法读取凭证 JSON；请检查文件和格式") from None


def github_preflight():
    """Reject queued snapshots older than the stored Secret; never roll them back."""
    from datetime import datetime
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    run_id = os.environ.get("GITHUB_RUN_ID", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not run_id.isdigit():
        raise AuthError("GitHub 运行上下文无效")
    try:
        def metadata(endpoint):
            result = subprocess.run(["gh", "api", endpoint], capture_output=True, timeout=30, shell=False)
            if result.returncode:
                raise ValueError()
            return json.loads(result.stdout)
        secret = metadata(f"repos/{repo}/actions/secrets/WORKBUDDY_AUTH")
        run = metadata(f"repos/{repo}/actions/runs/{run_id}")
        updated = datetime.fromisoformat(secret["updated_at"].replace("Z", "+00:00"))
        queued = datetime.fromisoformat(run["created_at"].replace("Z", "+00:00"))
    except (OSError, subprocess.SubprocessError, ValueError, KeyError, TypeError, AttributeError):
        raise AuthError("无法检查 GitHub Secret 快照；需要 Secrets 读写和 Actions 只读权限") from None
    if updated >= queued:
        raise AuthError("此运行的 Secret 快照可能已过期；请发起全新的运行，勿重跑旧任务")


def sync_github(path):
    """gh encrypts the file for GitHub; never put credential contents in argv/logs."""
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    if not re.fullmatch(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+", repo) or not os.environ.get("GH_TOKEN"):
        raise AuthError("持久化需要 GITHUB_REPOSITORY 和具有该仓库 Secrets 写权限的 GH_TOKEN")
    # Validate without normalizing: persistence must preserve disabled/note state.
    read_auth(path)
    for attempt in range(3):
        try:
            with open(path, "rb") as source:
                result = subprocess.run(["gh", "secret", "set", "WORKBUDDY_AUTH", "--repo", repo],
                                        stdin=source, capture_output=True, timeout=30, shell=False,
                                        creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            if result.returncode == 0:
                return
        except (OSError, subprocess.SubprocessError):
            pass
        if attempt < 2:
            time.sleep(attempt + 1)
    raise AuthError("WORKBUDDY_AUTH 写回失败；新凭证已保存本地，必须恢复持久化后再运行，勿回退旧 Secret")


def write_auth(path, data, sync=True):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    fd, tmp = tempfile.mkstemp(prefix=".workbuddy-", suffix=".tmp", dir=path.parent)
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as stream:
            json.dump(data, stream, ensure_ascii=False, indent=2)
            stream.flush()
            os.fsync(stream.fileno())
        os.replace(tmp, path)
        if os.name != "nt":
            directory = os.open(path.parent, os.O_RDONLY)
            try:
                os.fsync(directory)
            finally:
                os.close(directory)
        if sync and os.environ.get("WORKBUDDY_PERSIST_GITHUB") == "1":
            sync_github(path)
    finally:
        if os.path.exists(tmp):
            os.unlink(tmp)


@contextlib.contextmanager
def auth_lock(directory):
    path = Path(directory)
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    with open(path / ".workbuddy.lock", "a+b") as stream:
        stream.seek(0)
        stream.write(b"0")
        stream.flush()
        stream.seek(0)
        try:
            if os.name == "nt":
                import msvcrt
                msvcrt.locking(stream.fileno(), msvcrt.LK_NBLCK, 1)
            else:
                import fcntl
                fcntl.flock(stream, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except OSError:
            raise AuthError("另一个签到进程正在使用凭证，请稍后重试") from None
        try:
            yield
        finally:
            if os.name == "nt":
                stream.seek(0)
                msvcrt.locking(stream.fileno(), msvcrt.LK_UNLCK, 1)
            else:
                fcntl.flock(stream, fcntl.LOCK_UN)
