# bs

毕业设计项目仓库。

当前仓库已整理为“源码可提交、环境不入库”的状态：本地虚拟环境、日志、构建产物、虚拟机镜像及 `vm/` 下的环境文件均已排除，不会随 Git 一起上传。

## 仓库结构

```text
bs/
├─ kylin-safeops/    项目源码
├─ info/             补充资料
└─ vm/               本地虚拟机与迁移环境（已忽略，不上传）
```

## 项目说明

`kylin-safeops` 是本仓库的主体项目，包含：

- `backend/`：FastAPI 后端
- `frontend/`：React + Vite 前端
- `scripts/`：本地启动、停止、兼容性检查、迁移辅助脚本
- `deploy/`：Docker 与麒麟环境部署说明
- `data/`：审计与回放数据目录（仓库仅保留占位文件）
- `docs/`：项目文档

## 本地启动

进入项目目录：

```powershell
cd E:\bs\kylin-safeops
```

推荐用项目自带脚本启动：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev.ps1 start
```

启动后默认访问地址：

- 前端：<http://127.0.0.1:5173/>
- 后端：<http://127.0.0.1:8000/>
- 健康检查：<http://127.0.0.1:8000/health>

停止开发环境：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\stop_dev.ps1
```

查看状态：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\dev.ps1 status
```

## Docker 启动

如果本机已安装 Docker，也可以直接运行：

```powershell
cd E:\bs\kylin-safeops
docker compose up --build
```

## 提交说明

为避免仓库混入本地环境文件，以下内容默认不提交：

- `.venv/`
- `node_modules/`
- `dist/`、`build/`
- `logs/`
- `.env`
- `vm/`

如需查看项目内部更详细的模块说明，请继续阅读：

- [kylin-safeops/README.md](E:\bs\kylin-safeops\README.md)
