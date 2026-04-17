# Xboard OAuth Plugin

该仓库提供 Xboard / Niceboard 的 OAuth 登录插件，支持以下第三方平台：

- Google
- GitHub
- LinuxDO Connect

插件负责以下能力：

- 后台插件配置项
- OAuth 授权与回调路由
- 第三方账号与站内账号绑定
- 向已登录用户提供第三方账号绑定与解绑接口
- 首次第三方登录时自动注册站内账号
- 向前端公开可用的 OAuth 提供方列表

## 仓库结构

本仓库根目录就是插件目录内容。部署时应将整个仓库内容放入目标项目的 `plugins/Oauth` 目录中，目录层级应如下：

```text
plugins/
  Oauth/
    Plugin.php
    config.json
    Controllers/
    Services/
    routes/
    database/
```

## 安装方法

### 方法一：直接克隆到插件目录

在目标项目根目录执行：

```bash
git clone https://你的仓库地址/Xboard-Oauth.git plugins/Oauth
```

完成后，在后台插件管理中安装并启用 `OAuth 登录` 插件。

### 方法二：先下载仓库，再复制到插件目录

1. 下载本仓库源码压缩包，或先克隆到任意本地目录。
2. 将仓库内全部文件复制到目标项目的 `plugins/Oauth`。
3. 确认 `plugins/Oauth/Plugin.php` 与 `plugins/Oauth/config.json` 已存在。
4. 在后台插件管理中安装并启用 `OAuth 登录` 插件。

## 后台配置步骤

1. 进入后台插件管理。
2. 安装并启用 `OAuth 登录` 插件。
3. 分别填写 Google、GitHub、LinuxDO Connect 的 `Client ID` 与 `Client Secret`。
4. 按需打开对应平台开关并保存。
5. 首次安装或升级时会执行插件内迁移，为 `v2_user` 表增加以下字段，并将 `email` 字段长度扩展为 `191`：
   - `google_id`
   - `github_id`
   - `linuxdo_id`
6. 若启用 Google、GitHub 或 LinuxDO Connect，可分别设置各自的“首次登录模式”：
   - `direct_register`：首次登录且站内不存在可直接绑定的站内账号时，允许创建新账号并完成绑定
   - `bind_existing`：首次登录时仅允许绑定已存在的站内账号，不创建新账号

## 回调地址

请在第三方平台控制台中配置以下回调地址：

- `https://你的域名/api/v1/passport/auth/oauth/google/callback`
- `https://你的域名/api/v1/passport/auth/oauth/github/callback`
- `https://你的域名/api/v1/passport/auth/oauth/linuxdo/callback`

## 前端要求

该插件只提供后端 OAuth 能力与配置数据，不会自动修改任意主题页面。前端若要真正显示第三方登录入口，必须满足以下条件。

### 1. 登录页和注册页都要有 OAuth 入口

前端需要在登录页、注册页分别渲染第三方登录按钮。若主题没有这些按钮，用户虽然可以在后台完成配置，但页面上不会出现入口。

### 2. 前端必须读取可用提供方列表

插件会通过访客配置接口公开已启用的提供方：

```text
/api/v1/guest/comm/config
```

前端需要读取返回数据中的：

```json
{
  "data": {
    "oauth_providers": [
      {
        "driver": "google",
        "label": "Google"
      }
    ]
  }
}
```

前端应根据 `oauth_providers` 动态决定显示哪些按钮。

### 3. 按钮点击后要跳转到插件授权地址

登录页按钮应跳转到：

```text
/api/v1/passport/auth/oauth/{driver}/redirect?scene=login&redirect=dashboard
```

注册页按钮应跳转到：

```text
/api/v1/passport/auth/oauth/{driver}/redirect?scene=register&redirect=dashboard
```

如果站点启用了邀请码注册，注册页还应在跳转时附带：

```text
invite_code=当前表单中的邀请码
```

### 4. 前端需要处理 OAuth 错误信息

当授权失败、邮箱未返回、邮箱未验证或邀请码不满足条件时，插件会将用户重定向回前端登录页或注册页，并在地址中附带 `oauth_error`。

前端应在登录页和注册页读取该参数，并明确展示错误信息。

当提供方处于 `bind_existing` 模式，且当前站内不存在可直接绑定的账号时，插件还会额外附带：

- `oauth_hint=bind_existing`
- `oauth_provider={driver}`

前端应明确提示用户：需要先登录已有账号，再前往个人中心完成绑定。

### 5. 前端需要在个人中心提供绑定入口

由于前端登录态通常通过 `Authorization Bearer` 请求头传递，浏览器直接跳转到 OAuth 授权地址时不会自动携带该请求头，因此个人中心不能直接跳转到 `/passport/auth/oauth/{driver}/redirect`。

推荐接入方式如下：

1. 已登录用户先调用：

```text
/api/v1/user/oauth/{driver}/bind
```

接口会返回：

```json
{
  "data": {
    "bind_token": "..."
  }
}
```

2. 前端再跳转到：

```text
/api/v1/passport/auth/oauth/{driver}/redirect?scene=bind&bind_token=...
```

3. 绑定成功或失败后，插件会回跳到：

- `#/app/profile?oauth_success=...`
- `#/app/profile?oauth_error=...`

4. 若需要展示当前绑定状态或提供解绑按钮，可调用：

```text
GET  /api/v1/user/oauth/bindings
POST /api/v1/user/oauth/{driver}/unbind
```

### 6. 当前实现默认使用哈希路由

插件回跳前端时，默认地址格式为：

- `https://你的域名/#/login`
- `https://你的域名/#/register`
- `https://你的域名/#/app/profile`

因此，当前实现默认适配使用 `#/login`、`#/register` 的前端主题。如果你的主题不是这一套路由结构，需要同步调整插件中的回跳地址生成逻辑。

## 主题适配说明

### Vueboard

当前 `Vueboard` 版本已经接入 OAuth 入口，只要插件启用并完成配置，登录页与注册页就会显示第三方登录按钮。

### Xboard

原始 `Xboard` 前端默认不会自己出现 OAuth 按钮。若要在 `Xboard` 中使用本插件，需要额外加入前端入口脚本或等价实现。

换言之，`原版 Xboard + 仅安装插件 + 不做任何前端修改`，不能直接显示 OAuth 登录入口。

## 账号规则说明

- `google_id`、`github_id`、`linuxdo_id` 保存的是第三方平台用户唯一标识，不是邮箱。
- 邮箱用于查找和绑定已有站内账号。
- 若站内已存在同邮箱账号，则会绑定到现有账号。
- 若站内不存在该邮箱账号，且该渠道处于 `direct_register` 模式，则会自动创建新账号。
- 若该渠道处于 `bind_existing` 模式，则会要求用户先登录现有账号后再完成绑定。
- 首次通过 OAuth 自动创建账号时，会生成一段随机本地密码并保存哈希值。

## 适用范围

本插件适合以下场景：

- 希望将 OAuth 配置放在插件管理页中维护
- 希望同时支持 Google、GitHub、LinuxDO Connect
- 前端主题已经具备 OAuth 按钮接入能力，或准备自行补充这一部分
