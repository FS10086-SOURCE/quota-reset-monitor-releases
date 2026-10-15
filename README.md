# 重置雷达

**Reset Radar / Quota Reset Monitor** 是一款免费的 Windows 桌面工具，用小悬浮窗查看 Codex 额度重置公告、个人周期预测和历史日历。非 OpenAI 官方产品。

## 下载与安装

[下载最新版 Windows x64 安装包](https://github.com/FS10086-SOURCE/quota-reset-monitor-releases/releases/latest) · [查看 0.1.15 更新说明](https://github.com/FS10086-SOURCE/quota-reset-monitor-releases/releases/tag/v0.1.15)

在发行页面下载文件名以 `x64-setup.exe` 结尾的安装包，运行后按提示安装。应用使用 Microsoft Edge WebView2 Runtime，并提供应用内更新；更新包经过固定公钥签名校验。

## 功能

- 查看公共重置公告与最近的预测日期或区间，当天完成情况显示在卡片角标。
- 记录个人上次重置日期、校准周期预测，在历史日历中回看记录。
- 小悬浮窗可收起到屏幕四边，双击展开，位置和收起状态会保留。
- 在应用内查看来源帖子；可选摘要翻译在本机运行，模型需另行下载。
- 视频工具支持公开网页和 m3u8 链接，网页包含多个视频时可选择其中一个下载。

视频工具首次使用需下载约 208 MiB 的 yt-dlp 和 FFmpeg 组件，支持静态系统代理；PAC/WPAD 自动代理脚本、需登录内容、直播及 DRM 视频暂不支持。下载前请确认你有权保存该内容。

## 数据与来源

个人记录保存在本机。公共公告和预测受来源收录与网络更新影响，公共消息不代表你的账户已经到账；个人日期需要自行确认或校准。公共来源包括 [Codex Reset Radar](https://codexreset.today/)。

本仓库提供公开安装包、更新元数据和发布辅助文件，应用源码保持私有。更新签名不等同于 Windows Authenticode 发布者证书。

## 反馈

遇到问题可在 [Issues](https://github.com/FS10086-SOURCE/quota-reset-monitor-releases/issues) 提交应用版本、复现步骤和经过脱敏的截图。请勿上传密码、令牌或个人数据库。
