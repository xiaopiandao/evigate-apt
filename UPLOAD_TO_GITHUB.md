# GitHub 仓库与投稿引用

公开仓库：<https://github.com/xiaopiandao/evigate-apt>。本地 Git 仓库位于 `output/github/evigate-apt`，`main` 分支跟踪该远程仓库。

更新前先核对待提交文件；不要提交 `data/raw/`、密钥、模型权重、个人文件或未经核准的作者元数据：

```powershell
cd 'output/github/evigate-apt'
git status --short
git diff --stat
```

项目代码尚未选择许可证；公开可见不等于授权他人复用。`IEEEtran.cls` 保留自身 LPPL 声明。投稿用 `author_metadata.json` 的 `artifact_url` 应指向上述公开仓库；该文件还可能含私人联系信息，不应上传到公开仓库。
