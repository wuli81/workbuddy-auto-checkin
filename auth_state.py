"""Safe import/export and GitHub Secret persistence. Never print credentials."""
import argparse
import json
import os
from pathlib import Path
import sys
from workbuddy_auth import AuthError, normalize_auth, read_auth, write_auth, sync_github, github_preflight
from workbuddy_auth import safe_print as print


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    prepare = sub.add_parser("prepare", help="从环境变量导入并检查云端明文凭证")
    prepare.add_argument("path")
    export = sub.add_parser("export", help="在本机解密/精简导出；不修改桌面端源文件")
    export.add_argument("source")
    export.add_argument("destination")
    sync = sub.add_parser("sync", help="加密写回 WORKBUDDY_AUTH Secret")
    sync.add_argument("path")
    sync.add_argument("--preflight", action="store_true", help="拒绝已过期的运行 Secret 快照")
    args = parser.parse_args()
    try:
        if args.command == "prepare":
            data = json.loads(os.environ.get("WORKBUDDY_AUTH", ""))
            auth = data.get("auth", data) if isinstance(data, dict) else {}
            if not isinstance(auth, dict) or any(isinstance(auth.get(k), dict) for k in ("accessToken", "refreshToken")):
                raise AuthError("云端无桌面运行时：请先在本机运行 auth_state.py export 再更新 Secret")
            data = normalize_auth(data)
            if data["disabled"]:
                raise AuthError("凭证已失效，需要重新登录")
            write_auth(args.path, data, sync=False)
            print("凭证格式检查通过（尚未验证服务器会话）")
        elif args.command == "export":
            if Path(args.source).resolve() == Path(args.destination).resolve() or Path(args.destination).exists():
                raise AuthError("导出目标必须为新文件，不能覆盖源文件或已有凭证")
            data = read_auth(args.source)
            if data["disabled"]:
                raise AuthError("源凭证已标记失效，需要重新登录")
            write_auth(args.destination, data, sync=False)
            print("已导出最小凭证；请通过文件或 Secret 传输，勿粘贴到聊天/日志")
        else:
            if args.preflight:
                github_preflight()
            sync_github(args.path)
            print("WORKBUDDY_AUTH 已安全写回")
        return 0
    except (ValueError, OSError):
        # Only AuthError is safe to display; JSON/OSError can include source data.
        error = sys.exc_info()[1]
        print(str(error) if isinstance(error, AuthError) else "凭证操作失败，请检查 JSON、路径和权限", file=sys.stderr)
        return 1


if __name__ == "__main__":
    sys.exit(main())
