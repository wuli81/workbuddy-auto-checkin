# WorkBuddy 自动签到

独立的 WorkBuddy / CodeBuddy 签到、积分查询和会话刷新工具。正常云端运行只用 Python 标准库，不需要安装或启动桌面客户端。

## 认证与长期运行方案

2026-10-22 检查发现两类独立问题：

- 服务端返回 `12153` 表示会话已失效，需要重新登录。修改本地解密代码不能恢复已撤销的会话。
- 新客户端将 accessToken、refreshToken 以及部分个人信息保存为 `{$wbEncrypted:1,envelope:"..."}`。它是本地静态存储格式，不能直接作为 HTTP Bearer token，也不证明远端认证协议发生了同样的变化。
- 旧 Actions 工作流从固定 Secret 生成临时文件。刷新后的 refreshToken 如果不写回，下一次运行仍使用旧值。

**建议长期使用 VPS + 持久凭证文件 + systemd timer。** 每次轮换先原子写盘，目录锁阻止同机并发，运行不依赖桌面客户端或 GitHub Secrets 写权限。定时器使用北京时间，服务器关机期间错过的任务会在恢复后补触发；不会补签历史日期。

GitHub Actions 也支持即时写回 Secret，但 Secret 不是事务数据库：服务端已轮换、runner 突然销毁而尚未写回时，仍可能需要重新登录。GitHub 定时触发也可能延迟。不要承诺 token 永久有效，服务端仍可撤销会话。

## 获取最小凭证

### 独立浏览器登录（适合长期无人值守）

```bash
python3 login_quick.py cn --auth-dir auths
# 国际版使用 global
# macOS/Linux 也可 ./login.sh cn --auth-dir auths
```

按终端给出的一次性链接在浏览器完成授权。此流程不依赖桌面安装，仍需要本人完成登录，不能在 Actions 中无人交互地重新登录。独立自动化会话可减少桌面端与服务器同时轮换同一 refreshToken 的冲突；服务端的会话政策仍可能影响它。

登录脚本只保存 accessToken、refreshToken、过期时间、domain、uid、enterpriseId 和 disabled；不打印 token 前缀、手机号或昵称，不删除其他账号。文件保存在指定目录，避免旧版写死容器路径的问题。默认输出目录为当前目录的 `auths/`。

### 从已登录的桌面客户端导出

Windows PowerShell 示例（把 python 替换为本机 Python 命令）：

```powershell
python auth_state.py export "$env:LOCALAPPDATA\CodeBuddyExtension\Data\Public\auth\workbuddy-desktop.info" "auths\workbuddy-auth.json"
```

- 兼容旧明文和新版 accessToken / refreshToken 信封。加密昵称和手机号直接丢弃，不需要解密。
- 新版仅支持经过认证验证的 suite 1 / sym-v1 字段信封；未来未知格式会明确失败，不猜测解密方式。
- 解密在匹配版本 WorkBuddy 自带 Electron 的子进程中完成；密钥不导出、不保存、不上传。必要时通过 `WORKBUDDY_EXE` 指定可信的客户端可执行文件。
- 实现使用客户端原生存储接口获取构建材料，校验 keyId，并使用相应 AAD 验证 AES-256-GCM 标签。其版本兼容性不能当作官方长期 API 保证。
- 导出不会修改源文件，不覆盖已有目标文件；会生成用于自动化的**明文最小凭证**。保护这个目录，按凭证管理，不要提交仓库、发聊天、上传 artifact 或使用 Actions cache 保存。
- VPS / GitHub 上没有匹配客户端时，请传输已经导出的最小凭证。单独复制加密信封不能解密，复制桌面安装包或导出全局解密密钥也不是推荐部署方式。
- 一份 refreshToken 只由一个自动化实例管理。桌面端和服务器共享同一会话可能出现轮换冲突，优先采用独立浏览器登录。

支持嵌套或扁平旧 JSON。过期时间自动兼容秒/毫秒。示例参见 [auth.example.json](auth.example.json)。

## 使用

```bash
python3 workbuddy_checkin.py signin auths
python3 workbuddy_checkin.py credit auths
python3 workbuddy_checkin.py credit auths -j
python3 workbuddy_checkin.py refresh auths
python3 workbuddy_checkin.py trial <uid> auths  # 仅 Global
python3 workbuddy_checkin.py cron 9 auths       # 当前系统时区；VPS 推荐 systemd
```

- 从 `workbuddy-*.json` / `workbuddy.json` 读取账号；CN 支持签到，Global 保留 trial 和积分功能。
- 到期前 5 天预刷新；401 时最多再刷新重试一次。12153 在 HTTP 200 或 401 响应中都视为会话失效，保存 disabled，停止继续调用。
- 刷新落盘前使用随机临时文件、flush/fsync 和原子替换；POSIX 凭证文件权限 0600。使用独立账号和受限目录管理 Windows ACL。
- 无效凭证、已失效账号、缺少文件、刷新或持久化失败会返回失败状态，避免任务假成功。
- 凭证值、个人信息和上游原始错误响应不进入日志；Bark 请求异常不输出包含设备 key 的 URL。Bark 通知内容也经过脱敏。
- 内置 cron 修复跨月底日期计算；任务失败后继续等待下次执行。服务端会话失效仍须本人重新授权。

## VPS：推荐部署

模板位于 [deploy/](deploy/)。以下示例假定代码放在 `/opt/workbuddy-auto-checkin`：

```bash
sudo useradd --system --home /var/lib/workbuddy-checkin --shell /usr/sbin/nologin workbuddy
sudo install -d -o workbuddy -g workbuddy -m 700 /var/lib/workbuddy-checkin/auths
# 安全传输已登录的凭证文件后：
sudo install -o workbuddy -g workbuddy -m 600 /secure/path/workbuddy-auth.json /var/lib/workbuddy-checkin/auths/workbuddy-auth.json
sudo install -m 644 deploy/workbuddy-checkin.service /etc/systemd/system/
sudo install -m 644 deploy/workbuddy-checkin.timer /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl start workbuddy-checkin.service
sudo systemctl enable --now workbuddy-checkin.timer
sudo systemctl list-timers workbuddy-checkin.timer
```

定时为 `09:07 Asia/Shanghai`，不修改服务器系统时区。服务用专用无登录账号、受限可写目录和权限运行。可选 Bark 地址写入 root 管理、0600 权限的 `/etc/workbuddy-checkin.env`，内容为 `BARK_URL=...`，不要写在命令行或公开配置里。

迁移后停用原来的 GitHub 定时工作流，并确保没有另一个容器/cron 使用同一会话。凭证目录需要受限备份；不要从旧备份恢复已被轮换的 refreshToken。监控 systemd 失败状态或 Bark 失败通知；12153 后重新登录并替换失效凭证。

Docker 也可使用现有 compose 的 `./auths:/app/auths` 持久卷。容器需要保护宿主凭证目录，避免同时启动多个使用同一会话的副本。

## GitHub Actions：可选部署

仓库 Settings → Secrets and variables → Actions 配置：

| Secret | 内容 |
|---|---|
| WORKBUDDY_AUTH | 已重新登录、导出的最小 JSON；不是加密信封或旧失效会话 |
| WORKBUDDY_SECRETS_TOKEN | 仅授权此仓库的 fine-grained PAT：Secrets 读写、Actions 只读；设置到期提醒 |
| BARK_URL | 可选，Bark 地址 |

使用 [GitHub Secrets API](https://docs.github.com/en/rest/actions/secrets#create-or-update-a-repository-secret) 所需的 Secrets 写权限；普通工作流 `GITHUB_TOKEN` 不提供这一能力。工作流利用 GitHub 托管 Ubuntu runner 的 `gh` CLI，通过标准输入加密设置 Secret。不要给 PAT 更大的仓库范围。

工作流行为：

1. 在 runner 临时目录创建受限文件，验证凭证为可用格式的明文最小导出。
2. 对照运行创建时间与 Secret 的更新时间，拒绝可能持有旧快照的排队任务；需要发起新运行，不能重跑旧任务覆盖新凭证。
3. 先写回当前凭证验证权限，成功后才允许调用可能轮换 token 的签到/刷新端点。
4. 每次刷新或 disabled 状态变更立即写回 Secret；失败时保留 runner 本地新文件并让任务报错，末尾再尝试保存。
5. 最后清理临时文件。不会提交、缓存或上传凭证。跨分支的统一 concurrency group 阻止同仓库工作流并发轮换。

仅适用于**单账号、单 Secret、单一管理者**。运行期间不要从其他机器修改同一 Secret。并发组不能协调桌面客户端、其他仓库或 VPS；不要让这些环境共享同一会话。Runner 突然销毁、GitHub API 长期不可用等情形仍可能丢失最后一次轮换，这是推荐 VPS 的原因。权限过期时任务会在远端刷新前失败，避免静默轮换后丢失。

GitHub [定时事件](https://docs.github.com/en/actions/reference/workflows-and-actions/events-that-trigger-workflows#schedule) 可能延迟。保留 UTC 01:07 的原设置，不承诺北京时间 09:07 准时执行。

## 验证与来源

```bash
python3 -m unittest discover -s tests -v
```

测试使用虚构凭证；覆盖明文/混合加密、毫秒到期、GCM 篡改、轮换重新加载、12153、即时 Secret 写回及失败保护、旧快照拒绝、日志脱敏、账号保留和进程互斥。Node 仅用于合成加密信封测试，正常云端运行不需要 Node。PR CI 在 Windows 和 Ubuntu 运行，不读取任何仓库 Secret。

解密助手改编自 [88lin/workbuddy-auto-signin](https://github.com/88lin/workbuddy-auto-signin/blob/main/signin.py)，保留 MIT 版权声明于 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)。API 路由保留原有 cpa-plugin/workbuddy 来源。使用固定的 CN / Global 服务地址，不按凭证内容向任意主机发送 token。

MIT License。

