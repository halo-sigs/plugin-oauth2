# plugin-oauth2

Halo 2.0 的 Oauth2 第三方登录插件。

## 开发环境

插件开发的详细文档请查阅：<https://docs.halo.run/developer-guide/plugin/hello-world>

```bash
git clone git@github.com:halo-sigs/plugin-starter.git

# 或者当你 fork 之后

git clone git@github.com:{your_github_id}/plugin-starter.git
```

```bash
cd path/to/plugin-starter
```

```bash
# macOS / Linux
./gradlew pnpmInstall

# Windows
./gradlew.bat pnpmInstall
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
      - "/path/to/plugin-starter"
```

## 如何使用

1. 安装此插件
2. 前往 GitHub [创建 OAuth App](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/creating-an-oauth-app)
   ，填写相关
   信息，并将 `Authorization callback URL` 的值填写为 `https://{your-domain}/login/oauth2/code/github`。
   如果是本地测试填写为 `http://127.0.0.1/login/oauth2/code/github` ，不能是 `localhost`
   ，参考： [authorizing-oauth-apps](https://docs.github.com/en/apps/oauth-apps/building-oauth-apps/authorizing-oauth-apps)。
3. 填写 Client ID 和 Client Secret
