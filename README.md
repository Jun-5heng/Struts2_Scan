# Struts2_Scan
# Struts2框架全系列漏洞扫描工具

## Code By:Jun_sheng @橘子网络安全实验室

橘子网络安全实验室 https://0range.team/

#### 0x00 风险概述

本工具仅限授权安全测试使用,禁止未授权非法攻击站点

在线阅读[《中华人民共和国网络安全法》](http://wglj.pds.gov.cn//upload/files/2020/4/1415254915.docx)

#### 0x01 工具使用

除必备三方库外，需要安装click库才能正常使用

本工具未设置默认路径，测试路径请尽可能准确到Struts2框架的文件上

python main.py -h获取工具使用帮助，实在不行你GitHub联系我，我教你用

![1.png](img/1.png)

pycharm中使用需要以main.py所在目录创建项目才能进行使用

或者你打个EXE直接双击

目前支持漏洞如下：

![2.png](img/2.png)

#### 0x02 Bug问题

Bug请提交Issues，有时间会看的

#### 0x03 持续性开发

1. 计划增加GUI界面，但是我现在不会，还不知道猴年马月学

2. Payload进行免杀改编，一样我现在还不会，不知道猴年马月学

#### 0x04 版本更新

1. 修改S2_059利用类相关bug

2. 修改S2_045利用类命令执行架构（v0.2.1）

3. 修改部分Payload为免杀Payload（v0.2.1）
