# 上传到 GitHub

此目录已初始化为本地 Git 仓库，但**没有**替你创建远程仓库或提交；这样提交作者信息仍由你控制。

1. 在 GitHub 新建一个**空仓库**，暂时不要勾选自动生成 README、`.gitignore` 或许可证。
2. 在 PowerShell 中进入本目录并核对待提交文件：

```powershell
cd 'path\to\evigate-apt'
git status --short
git add .
git diff --cached --stat
```

3. 确认没有 `data/raw/`、密钥、模型权重或个人文件后，用你自己的 Git 身份提交并连接远程：

```powershell
git commit -m "Release EviGate-APT research code"
git remote add origin https://github.com/YOUR_ACCOUNT/YOUR_REPOSITORY.git
git push -u origin main
```

若 Git 提示缺少身份，仅在**本仓库**中设置你自己的姓名和邮箱：

```powershell
git config user.name 'Your Name'
git config user.email 'you@example.com'
```

`evigate-apt-upload.zip` 是便于传输/解压的副本。若通过 GitHub 网页上传，请先在本机解压后上传**文件内容**；直接上传 ZIP 只会在仓库里得到一个压缩包，不会形成可浏览的代码树。

目前未添加项目代码许可证，需由作者决定后再公开授权。`IEEEtran.cls` 保留其自身 LPPL 声明。公开 URL 生成后，再把它写入投稿用的 `author_metadata.json` 的 `artifact_url` 字段；不要上传含作者私人联系方式或未核准信息的元数据文件。
