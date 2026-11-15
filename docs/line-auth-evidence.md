# 柏讯产物构建线鉴权与计费证据（公开清单之外的逐字记录）

> 本文件是 `line-manifest.json` 自由文本字段的**逐字**归档。清单的每个字符串都可能匿名公开，
> 所以那些字段已从清单里删除（2026-11-15，任务=converge-line-identity-and-keys 的公开载荷清理批次 I）。
> 本线今天有**两条**暴露路径需要知道：仓内 `line-manifest.json` 被 `gen_line_manifests_configmap.py`
> 逐字节投影进 `fd-prod/line-manifests`（平台 pod 挂在 `/etc/line-manifests/wire-build/`），
> 而线自己的 `/.well-known/line-manifest.json` **尚未实现**（2026-11-15 线内实测 404，镜像里也没有清单）。
> 所以这次删除收窄的是**投影面**，不是某个已经存在的公网正文。本文件不随镜像发布、不进门投影。

## `note` — 顶层 note

```text
柏讯产物构建与数据治理面：form/record-view/dashboard/doc 的创建·更新·发布 + 产物版本读取 + 数据集列事实 + 按需建集 + 表单数据管理。**无回退轨是真实缺口**：本面每个动作都要求用户级身份（产物归属某个客户/成员），线自有的 `wdk-` 数据面钥匙只覆盖只读数据且不承载成员身份，不能当回退。修法=给柏讯客户面加线自有 PAT（承载 owner 归属），或让 `wdk-` 键能承载 owner。
```

## `identity.note` — identity.note

```text
本仓只做**「有 Bearer 就放行」的传输门**，不解析、不验签（auth_gate.py:1-13 自述「上游权威」），并把这个 bearer 原样转发给柏讯客户面（client.py:26-55、tools_steward.py:57-216）。真实鉴权在 fd-wire：客户面要**用户级** Logto ID token（client.py:26 明确提示「壹座同租户登录后获取」）。无断言兑换端点，jit_policy=off。
```

## `auth_tracks[0].note` — auth_tracks[0].note（ciyuan-sk 客户轨）

```text
未接：本仓不解析入站凭据；词元钥匙会被原样转发到 fd-wire，由上游决定认不认。
```

## `billing.note` — billing.note

```text
本仓零计费代码（grep `sub2api` 无命中）：按调用扣费发生在网关/registry 的词元平面，不在本线代码里。上游 402 会被映射成 `billing` 错误（client.py:94），说明钱在 fd-wire/词元平面判。
```
