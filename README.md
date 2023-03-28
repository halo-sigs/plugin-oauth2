# plugin-oauth2

Halo 2.0 的 OAuth2 第三方登录插件。

## 使用方法

1. 在 [Releases](https://github.com/halo-sigs/plugin-oauth2/releases) 下载最新的 JAR 文件。
2. 在 Halo 后台的插件管理上传 JAR 文件进行安装。
3. 进入 Console 端的用户管理，点击右上角的 `认证方式` 按钮进入认证方式管理列表即可看到当前插件提供的认证方式。
4. 按照下方的配置指南配置所需的认证方式并启用。
5. 进入当前登录用户的个人资料页面，即可绑定已启用的认证方式。

## 配置指南

目前支持的认证方式：

| 服务商 | 文档                                                                                                                                                   | Halo 所需配置               | 回调地址                              |
| ------ | ------------------------------------------------------------------------------------------------------------------------------------------------------ | --------------------------- | ------------------------------------- |
| GitHub | [https://docs.github.com](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app)                                        | `Client ID` `Client Secret` | `<SITE_URL>/login/oauth2/code/github` |
| GitLab | [https://docs.gitlab.com](https://docs.gitlab.com/ee/integration/oauth_provider.html#configure-gitlab-as-an-oauth-20-authentication-identity-provider) | `Client ID` `Client Secret` | `<SITE_URL>/login/oauth2/code/gitlab` |
| Gitee  | <https://gitee.com/oauth/applications>                                                                                                                   | `Client ID` `Client Secret` | `<SITE_URL>/login/oauth2/code/gitee`  |

## 开发环境

插件开发的详细文档请查阅：<https://docs.halo.run/developer-guide/plugin/hello-world>

```bash
git clone git@github.com:halo-sigs/plugin-oauth2.git

# 或者当你 fork 之后

git clone git@github.com:{your_github_id}/plugin-oauth2.git
```

```bash
cd path/to/plugin-oauth2
```

```bash
# macOS / Linux
./gradlew build

# Windows
./gradlew.bat build
```

修改 Halo 配置文件：

```yaml
halo:
  plugin:
    runtime-mode: development
    fixedPluginPath:
      - "/path/to/plugin-oauth2"
```
