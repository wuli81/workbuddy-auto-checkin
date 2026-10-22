#!/usr/bin/env python3
"""Create a separate OAuth session without requiring the desktop client."""
import argparse
import base64
import json
from pathlib import Path
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
from workbuddy_auth import AuthError, auth_lock, normalize_auth, write_auth

CLIENT_UA = "CLI/2.63.2 CodeBuddy/2.63.2"


def request(method, url, headers=None):
    req = urllib.request.Request(url, data=b"{}" if method == "POST" else None, method=method)
    for key, value in {"Accept": "application/json", "Content-Type": "application/json",
                       "User-Agent": CLIENT_UA, **(headers or {})}.items():
        req.add_header(key, value)
    try:
        with urllib.request.urlopen(req, timeout=15) as response:
            data = json.load(response)
        if not isinstance(data, dict):
            raise ValueError()
        return data
    except (OSError, ValueError):
        raise AuthError("登录请求失败；请检查网络或稍后重试（响应内容已隐藏）") from None


def login(region, directory, timeout=900):
    base = "https://copilot.tencent.com" if region == "cn" else "https://www.workbuddy.ai"
    state = request("POST", base + "/v2/plugin/auth/state?platform=CLI")
    details = state.get("data")
    if state.get("code") != 0 or not isinstance(details, dict):
        raise AuthError("无法建立登录授权状态")
    opaque = details.get("state") or details.get("State")
    url = details.get("authUrl") or details.get("auth_url") or details.get("AuthURL")
    if not isinstance(opaque, str) or not isinstance(url, str) or not url.startswith("https://"):
        raise AuthError("登录授权响应格式无效")
    # This one-use login URL must be shown to the person completing authorization.
    print("请在浏览器中打开以下一次性链接完成登录；不要分享该链接：", flush=True)
    print(url, flush=True)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        response = request("GET", base + "/v2/plugin/auth/token?" + urllib.parse.urlencode({"state": opaque}))
        if response.get("code") == 11217:
            time.sleep(3)
            continue
        if response.get("code") != 0 or not isinstance(response.get("data"), dict):
            raise AuthError("登录授权失效或被拒绝，请重新发起登录")
        tokens = response["data"]
        access = tokens.get("accessToken") or tokens.get("access_token")
        if not access:
            time.sleep(3)
            continue
        break
    else:
        raise AuthError("登录等待超时，请重新运行")
    claims = {}
    try:
        claims = json.loads(base64.urlsafe_b64decode(access.split(".")[1] + "==="))
    except (ValueError, IndexError, AttributeError):
        pass
    account = request("GET", base + "/v2/plugin/login/account?" + urllib.parse.urlencode({"state": opaque}),
                      {"Authorization": "Bearer " + access})
    profile = account.get("data") if account.get("code") == 0 else {}
    if not isinstance(profile, dict):
        profile = {}
    uid = profile.get("uid") or profile.get("UID") or claims.get("uid") or claims.get("sub")
    if not uid:
        raise AuthError("无法获取账号标识；未覆盖已有凭证")
    expiry = int(tokens.get("expiresIn") or tokens.get("expires_in") or 0)
    data = normalize_auth({"auth": {
        "accessToken": access,
        "refreshToken": tokens.get("refreshToken") or tokens.get("refresh_token"),
        "expiresAt": int(time.time()) + expiry if expiry > 0 else claims.get("exp", 0),
        "domain": tokens.get("domain") or ("codebuddy.cn" if region == "cn" else "workbuddy.ai"),
    }, "account": {"uid": uid, "enterpriseId": profile.get("enterpriseId") or
                  profile.get("enterprise_id") or profile.get("EnterpriseID") or ""}, "disabled": False})
    destination = Path(directory) / ("workbuddy-" + data["account"]["uid"] + ".json")
    write_auth(destination, data, sync=False)
    print("登录成功，最小凭证已安全保存；其他账号文件已保留。")
    print("使用 workbuddy_checkin.py signin 执行签到。")
    return destination


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("region", choices=("cn", "global"), nargs="?", default="cn")
    parser.add_argument("--auth-dir", default="auths")
    parser.add_argument("--timeout", type=int, default=900)
    args = parser.parse_args()
    try:
        if not 3 <= args.timeout <= 1800:
            raise AuthError("登录等待时间必须介于 3 和 1800 秒")
        with auth_lock(args.auth_dir):
            login(args.region, args.auth_dir, args.timeout)
        return 0
    except (ValueError, OSError) as error:
        print(str(error) if isinstance(error, AuthError) else "登录失败（敏感内容已隐藏）", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())

