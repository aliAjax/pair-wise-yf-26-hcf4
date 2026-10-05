# 数字档案长期保存服务

仅使用 Python 3.11+ 标准库实现的独立档案保存项目，支持清单校验、真实 SHA-256 内容校验、多个离线副本、损坏检测与自动修复、格式迁移、保留期限和访问控制。

## 运行

```bash
python3 app.py --init --seed
python3 app.py
```

服务地址为 <http://127.0.0.1:8102>，默认数据库 `preservation.db`。测试：

```bash
python3 -m unittest -v
```

演示用户：`owner`、`archivist`、`auditor`、`outsider`。API 使用 `X-User-Id`。文件通过 Base64 提交，单文件上限 10 MiB；这是为了保持示例自包含，生产部署应换成对象存储和流式上传。

## 主要接口

- `POST /api/archives`：创建受限档案。
- `POST /api/archives/{id}/members`：所有者授予 read/write 权限。
- `POST /api/archives/{id}/versions`：提交文件清单，服务端重新计算哈希和大小。
- `GET /api/versions/{id}`：查看版本、文件清单和副本状态。
- `POST /api/versions/{id}/copies`：创建独立副本内容。
- `POST /api/copies/{id}/verify`：校验副本；发现损坏时从健康副本修复。
- `POST /api/copies/{id}/simulate-corruption`：演示/测试介质损坏，仅 owner 或 archivist 可用。
- `POST /api/versions/{id}/migrate`：生成格式迁移后的新版本并保留派生关系。
- `GET /api/archives/{id}/status`：保留期限、版本状态和审计记录。

## 销毁工作流

一份档案同时保存在服务端主副本和两个离线存储库（共 3 个存储点）。销毁按 Saga 状态机执行：

1. `POST /api/versions/{id}/destruction`（owner/archivist）：管理员发起销毁申请，三个存储点的副本**一起进入待销毁状态**（`destruction_jobs` + 每点一条 `destruction_items`：pending/failed/done）。申请执行期间，该档案的上传、新建副本、迁移一律返回 `409 destruction_in_progress`，进程内互斥锁保证销毁执行串行。
2. `POST /api/destruction/jobs/{id}/run`：按"离线库 A → 离线库 B → 服务端主副本"的顺序逐点销毁；每个点独立事务，成功立即落库（`done`，attempts 累加）。任一点失败立即停止，该点停在 `failed`、后续点保持 `pending`，接口返回 `503 destruction_point_failed` 并携带当前进度；**在三个点全部成功之前不写销毁记录**。
3. 介质故障：`POST /api/storage/fault`（`{location, reason}`）模拟某存储点介质故障；恢复后 `POST /api/storage/recover` 清除故障。重跑 `run` 时只处理仍未完成（pending/本轮恢复的 failed）的点，已经 `done` 的点**绝不重复执行**。
4. 三个点全部成功时，在同一事务内删除主副本内容、版本/副本置为 `destroyed`、写销毁账目 `destruction_records`（销毁记录号 `DR-xxxxxx`、存储点数、销毁前不可变文件清单快照）、任务置为 `completed`。
5. `GET /api/destruction/jobs/{id}`：查看申请、各存储点状态/尝试次数/错误和销毁记录；`GET /api/destruction/jobs/{id}/reconcile`：对账页，把销毁账目与三个存储点的实物状态（副本 state、残留文件数、清单哈希）逐点核对，返回 `balanced` 与 `mismatches`，可发现"账目已销毁但实物残留""实物已销毁但条目未完成（重复销毁风险）"等漂移。
6. 已完成的任务重复 `run` 是幂等的（返回 `already: true`，不执行任何点）；已销毁版本不能再申请销毁或写入。

档案路径拒绝绝对路径和 `..`；同一版本副本位置唯一；没有健康副本时版本标记为 `degraded`；所有变更写入审计日志。
