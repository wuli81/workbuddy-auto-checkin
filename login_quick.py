#!/usr/bin/env python3
"""WorkBuddy 重新登录 — 获取新 Token 并保存凭证"""
import json, os, sys, time, urllib.request, urllib.error, datetime, base64

EP_AUTH_STATE = "https://copilot.tencent.com/v2/plugin/auth/state?platform=CLI"
EP_AUTH_TOKEN = "https://copilot.tencent.com/v2/plugin/auth/token?state="
CLIENT_UA = "CLI/2.63.2 CodeBuddy/2.63.2"
AUTH_DIR = "/workspace/workbuddy-checkin/auths"

def http(method, url, headers=None, data=None):
    req = urllib.request.Request(url, method=method)
    req.add_header("Accept", "application/json")
    req.add_header("User-Agent", CLIENT_UA)
    if headers:
        for k, v in headers.items():
            req.add_header(k, v)
    if method == "POST" and data is None:
        data = b"{}"
        req.add_header("Content-Type", "application/json")
    if data:
        if isinstance(data, str):
            data = data.encode("utf-8")
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            return resp.status, resp.read().decode("utf-8", errors="replace")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", errors="replace")
    except Exception as e:
        return 0, str(e)

print("=" * 60)
print("  WorkBuddy 重新登录")
print("=" * 60)

# 1. 获取 Auth State
print("\n[1/5] 获取登录授权状态...")
status, body = http("POST", EP_AUTH_STATE)
if status != 200:
    print(f"  失败: HTTP {status}")
    print(f"  {body[:300]}")
    sys.exit(1)

data = json.loads(body)
if data.get("code") != 0:
    print(f"  失败: code={data.get('code')} msg={data.get('msg')}")
    sys.exit(1)

auth_state = data["data"]["state"]
auth_url = data["data"]["authUrl"]
print(f"  [OK] State: {auth_state}")
print(f"\n{'='*60}")
print(f"  请在浏览器中打开以下链接完成登录：")
print(f"  {auth_url}")
print(f"{'='*60}")
print(f"\n  登录完成后脚本将自动检测（最多等待 15 分钟）...")
print(f"  看到 127.0.0.1 回调报错是正常的，服务端已记录登录状态\n")

# 2. 轮询 Token
poll_url = EP_AUTH_TOKEN + auth_state
start = time.time()
MAX_WAIT = 900  # 15 分钟
access_token = refresh_token = expires_in = domain = ""

while time.time() - start < MAX_WAIT:
    elapsed = int(time.time() - start)
    sys.stdout.write(f"\r  [2/5] 等待登录中... {elapsed}s / {MAX_WAIT}s")
    sys.stdout.flush()

    status, body = http("GET", poll_url)
    if status == 200:
        try:
            data = json.loads(body)
            code = data.get("code", -1)
            if code == 0:
                d = data.get("data", {})
                access_token = d.get("access_token") or d.get("accessToken", "")
                refresh_token = d.get("refresh_token") or d.get("refreshToken", "")
                expires_in = d.get("expires_in") or d.get("expiresIn", 0)
                domain = d.get("domain", "www.codebuddy.cn")
                if access_token:
                    print(f"\n\n  [OK] 登录成功！Token 已获取")
                    print(f"  Access Token: {access_token[:32]}...")
                    days = int(expires_in) / 3600 / 24 if expires_in else 0
                    print(f"  有效期: {expires_in}s ({days:.1f}天)")
                    print(f"  Domain: {domain}")
                    break
            else:
                msg = data.get("msg", "")
                if code == 11217:
                    pass  # 等待中
                elif code == 12153:
                    print(f"\n  会话已失效，state 可能已过期")
                    break
                else:
                    if elapsed < 30:  # 只在开头打印一次
                        print(f"\n  code={code} msg={msg[:80]}")
        except json.JSONDecodeError:
            pass
    elif status == 404:
        print(f"\n  404: {body[:200]}")
        break

    time.sleep(3)
else:
    print(f"\n\n  超时！{MAX_WAIT}秒内未完成登录")
    sys.exit(1)

if not access_token:
    print(f"\n  未能获取 Token")
    sys.exit(1)

expires_at = int(time.time()) + int(expires_in) if expires_in else 0

# 3. 解析账号信息
print(f"\n[3/5] 解析账号信息...")
account = {}
try:
    payload = access_token.split(".")[1]
    payload += "=" * (4 - len(payload) % 4)
    decoded = json.loads(base64.b64decode(payload))
    account = {
        "uid": decoded.get("uid", decoded.get("sub", "")),
        "enterpriseId": decoded.get("enterpriseId", ""),
        "nickname": decoded.get("nickname", decoded.get("name", "")),
    }
    print(f"  UID: {account['uid']}")
    print(f"  昵称: {account['nickname']}")
except Exception as e:
    print(f"  Token 解析失败: {e}")
    account = {"uid": "unknown", "enterpriseId": "", "nickname": "Unknown"}

# 4. 保存凭证
print(f"\n[4/5] 保存凭证...")
auth_data = {
    "auth": {
        "accessToken": access_token,
        "refreshToken": refresh_token,
        "expiresAt": expires_at,
        "domain": domain,
    },
    "account": account,
    "disabled": False,
}

os.makedirs(AUTH_DIR, exist_ok=True)
uid = account.get("uid", "unknown")
cred_path = os.path.join(AUTH_DIR, f"workbuddy-{uid}.json")

old_files = [f for f in os.listdir(AUTH_DIR) if f.startswith("workbuddy-") and f.endswith(".json")]
for f in old_files:
    os.remove(os.path.join(AUTH_DIR, f))
    print(f"  已删除旧凭证: {f}")

with open(cred_path, "w") as f:
    json.dump(auth_data, f, indent=2, ensure_ascii=False)
os.chmod(cred_path, 0o600)
print(f"  [OK] 凭证已保存: {cred_path}")
print(f"  Token 过期: {datetime.datetime.fromtimestamp(expires_at)}")

# 5. 验证 + 签到
print(f"\n[5/5] 验证并签到...")

# 先查签到状态
status, body = http("GET", 
    f"https://{domain}/v2/billing/meter/checkin-activity-status",
    headers={"Authorization": f"Bearer {access_token}"}
)
if status == 200:
    d = json.loads(body)
    if d.get("code") == 0:
        ci = d.get("data", {})
        print(f"  签到状态: 今日{'已签' if ci.get('today_checked', ci.get('todayChecked', False)) else '未签'}")
        print(f"  连签: {ci.get('streak_days', ci.get('streakDays', 0))} 天")
    else:
        print(f"  签到状态: code={d.get('code')}")
else:
    # 尝试 fallback
    status2, body2 = http("GET",
        f"https://{domain}/v2/billing/meter/checkin-status",
        headers={"Authorization": f"Bearer {access_token}"}
    )
    if status2 == 200:
        d = json.loads(body2)
        print(f"  签到状态(fallback): code={d.get('code')}")
    else:
        print(f"  签到状态: HTTP {status} / {status2}")

# 执行签到
status, body = http("POST",
    f"https://{domain}/v2/billing/meter/daily-checkin",
    headers={"Authorization": f"Bearer {access_token}"}
)
if status == 200:
    d = json.loads(body)
    code = d.get("code", -1)
    msg = d.get("data", {}).get("message", d.get("msg", ""))
    if code == 0:
        print(f"  [OK] 签到成功！{msg}")
    elif code == 11216 or "already" in str(msg).lower() or "已签到" in str(msg):
        print(f"  今日已签到")
    else:
        print(f"  签到: code={code} msg={msg}")
else:
    print(f"  签到: HTTP {status} {body[:150]}")

# 查询积分
status, body = http("GET",
    f"https://{domain}/v2/billing/meter/get-user-resource",
    headers={"Authorization": f"Bearer {access_token}"}
)
if status == 200:
    d = json.loads(body)
    if d.get("code") == 0:
        accounts = d.get("data", {}).get("Accounts", d.get("data", {}).get("accounts", []))
        if isinstance(accounts, list):
            total_remain = sum(a.get("remain", a.get("Remain", 0)) for a in accounts)
            total_size = sum(a.get("size", a.get("Size", 0)) for a in accounts)
            print(f"  积分: {total_remain} / {total_size} ({len(accounts)} 个套餐包)")
    else:
        print(f"  积分查询: code={d.get('code')}")
else:
    print(f"  积分查询: HTTP {status}")

print(f"\n{'='*60}")
print(f"  登录完成！凭证已更新")
print(f"  Token 有效期至: {datetime.datetime.fromtimestamp(expires_at)}")
print(f"{'='*60}")
