# 大坝巡检、缺陷与应急管理

安排巡检，记录渗流、位移、裂缝等缺陷并跟踪修复、复检和应急预案。多座大坝共用同一缺陷库，按**管理处（office）**做权限隔离。

## 模块结构

- `app.py`：参数解析、依赖组装和HTTP服务启动。
- `src/domain.py`：数据结构、错误、状态和基础校验。
- `src/rules.py`：状态机、角色矩阵、优先级、期限和关闭不变量。
- `src/repository.py`：SQLite建表、事务、版本控制、审计链、归属列与条件认领。
- `src/service.py`：归属与角色权限、回填/认领用例、并发控制和审计。
- `src/http_api.py`：JSON路由和统一错误响应。
- `src/audit.py`：UTC时间和SHA-256审计事件。
- `static/index.html`：最小演示页。
- `tests/`：完整流程、规则、失败测试与多管理处隔离测试。

## 初始化与启动

```bash
python3 app.py --db ./data.db --port 8316
```

默认端口为`8316`，首次启动自动建库。使用`X-Actor`、`X-Role`和`X-Office`请求头传递身份。旧库升级时自动补列，历史缺陷归属保持空（未认领），不默认对任何处开放。

## 管理处隔离规则

- 业务接口（列表、详情、记录、状态流转、审计）只返回与操作**本处**数据；跨处读取、加记录、审批、流转或改负责人一律 `403` 拒绝；所有接口必须带 `X-Office`。
- 审计按归属处过滤；即使指定 `item_id` 也先验归属，不允许借审计接口读别处缺陷。
- 巡检员在花名册中归属某处后，不能以另一处身份建档。
- 未认领历史缺陷（`office_id` 为空）对任何业务角色不可见、不可流转，只对 `admin` 可见。

## 历史数据回填与认领（admin）

1. `POST /api/admin/sections` `{section}`：登记本处的坝段映射（幂等；同一坝段映射到处不可更改，重复登记返回 `409`）。
2. `POST /api/admin/backfill`：按坝段映射把未认领缺陷批量回填到本处；映射到别处或无映射的跳过，**不能默认开放**。
3. 无法映射的缺陷只能由**原创建人花名册所在处**的管理员认领：先 `POST /api/admin/actors` `{actor, office_id}` 登记人员归属，再 `POST /api/items/{id}/claim` `{owner}` 指定负责人。
4. 归属解析顺序：坝段映射优先，其次创建人花名册；映射与花名册均不可变，因此**认领失败后重试沿用同一映射结果**（映射要求他处时，本处重试仍是拒绝）。
5. 两名管理员并发认领同一缺陷时以数据库条件更新（`WHERE office_id IS NULL`）保证**先到先得**，后来者 `409`；认领不改变缺陷 `status`/`version`，未认领缺陷保持原状态。
6. 认领、回填、负责人变更与对应审计在**同一事务**提交，不会只写一半；认领时该缺陷的历史审计一并补齐归属。

其他 admin 接口：`GET /api/admin/sections`、`GET /api/admin/unclaimed`、`POST /api/items/{id}/owner`（本处内负责人变更）。

## 主要接口

- `GET /health`
- `GET /api/items` / `POST /api/items`（建档须提供 `section` 坝段编号）
- `GET /api/items/{id}`
- `GET/POST /api/items/{id}/records`
- `POST /api/items/{id}/transition`，必须提交`expected_version`
- `GET /api/audit`

允许业务角色：inspector, dam_engineer, emergency_manager, viewer；管理处管理角色：admin。异常值比控制阈值越高，缺陷优先级越高；应急处置缺陷必须完成复检并记录证据后才能关闭。

## 测试

```bash
python3 -m unittest discover -s tests -v
```
