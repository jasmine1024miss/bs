# KylinSafeOps

面向麒麟操作系统运维 Agent 的可验证认知与安全执行框架。

## 开发定位

本工程采用“本机 Docker 开发 + KylinOS/openKylin 最终验证”的路线。

Docker 用于快速开发和前后端联调，但 Docker 容器共享宿主机内核，不等同于完整麒麟系统环境。比赛提交材料必须准备 KylinOS/openKylin 真实运行截图或录屏。

## 目录结构

```text
kylin-safeops/
  backend/          FastAPI 后端
  frontend/         React 运维驾驶舱
  docs/             项目文档
  deploy/
    docker/         Docker 开发环境
    kylin/          麒麟部署说明
  scripts/          辅助脚本
  data/
    audit/          审计报告
    replay/         回放数据
  assets/
    screenshots/    截图素材
```

## 本地启动

如果不想理解 Python 虚拟环境，直接用一键脚本：

```powershell
cd D:\content\bs\kylin-safeops
powershell -ExecutionPolicy Bypass -File .\scripts\dev.ps1 start
```

如果 `8000` 或 `5173` 已经有本项目服务在运行，脚本会直接复用，不会重复启动。

停止后台开发服务：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop_dev.ps1
```

停止脚本会优先停止脚本记录的 PID；没有 PID 文件时，会检查这两个端口上看起来属于 SafeOps 的进程。

状态检查：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev.ps1 status
```

默认使用 `SAFEOPS_MODE=auto`：Windows 本机会自动使用 demo adapter，Linux/Kylin 且系统工具齐全时自动切换到 real adapter。也可以用 Docker：

```powershell
cd D:\content\bs\kylin-safeops
docker compose up --build
```

如果 Windows 里 `docker` 不在 PATH，但 Docker Desktop 安装在 `D:\Docker`，可以使用：

```powershell
D:\Docker\Docker\resources\bin\docker.exe compose up --build
```

前端：

```text
http://localhost:5173
```

后端：

```text
http://localhost:8000
```

## DeepSeek 配置

不要把真实 API Key 写入代码或文档。运行时通过环境变量配置：

```text
DEEPSEEK_API_KEY
DEEPSEEK_ENABLED=true
```

默认 `DEEPSEEK_ENABLED=false`，系统使用规则兜底模式。只有显式设置为 `true` 且提供 `DEEPSEEK_API_KEY` 时，后端才会访问 DeepSeek。

## Linux/Kylin 兼容模式

运行模式由 `SAFEOPS_MODE` 控制：

```text
SAFEOPS_MODE=demo   使用可控样例数据，适合 Windows/Docker 开发
SAFEOPS_MODE=real   调用真实 systemctl/journalctl/ss/ps，适合 Kylin/openKylin
SAFEOPS_MODE=auto   自动探测环境，Linux 且工具齐全时走 real，否则走 demo
```

如果强制 `SAFEOPS_MODE=real` 但环境不满足真实工具条件，诊断接口会返回 real 模式不可用，不会静默切换到 demo。

当前环境探测接口：

```text
GET /api/environment/probe
```

建议路线：

```text
Windows 本机：SAFEOPS_MODE=auto 或 demo
Docker 联调：SAFEOPS_MODE=demo
openKylin/KylinOS 验证：SAFEOPS_MODE=auto 或 real
```

## Kylin 迁移预检包

现在不需要一直开虚拟机。Windows 本机继续开发即可；等 openKylin/KylinOS 环境可用后，先生成迁移包：

```powershell
cd D:\content\bs\kylin-safeops
powershell -ExecutionPolicy Bypass -File .\scripts\package_for_kylin.ps1
```

把 `D:\content\bs\vm\migration\kylin-safeops-src.zip` 拷到 Kylin/openKylin 后执行：

```bash
unzip kylin-safeops-src.zip
cd kylin-safeops
bash scripts/kylin_migration_precheck.sh
bash scripts/kylin_install_runtime.sh
bash scripts/kylin_migration_precheck.sh
```

迁移总报告和兼容性报告会生成到：

```text
data/kylin_migration_precheck_report.md
data/kylin_preflight_report.md
```

它会检查系统识别、systemd、`systemctl/journalctl/ss/ps`、Python/Node/npm、端口快照、后端健康检查、real adapter 条件以及迁移脚本完整性。端口冲突演示数据默认不创建，只在比赛演示虚拟机中手动执行：

```bash
SAFEOPS_CONFIRM_DEMO=true bash scripts/kylin_prepare_nginx_conflict.sh
```

详细步骤见 `deploy/kylin/部署说明.md`。
