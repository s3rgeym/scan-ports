### Port Scanner | 端口扫描工具

This tool scans a list of targets (IP addresses or domain names) for open ports. It supports CIDR notation, IP ranges, and custom port ranges. The tool outputs the open ports along with their service names.

该工具扫描目标列表（IP地址或域名）的开放端口。它支持CIDR表示法、IP范围和自定义端口范围。工具输出开放端口及其服务名称。

### Usage:

```bash
~/workspace/scan-ports
❯ echo 'example.com' | go run main.go -p -10000

example.com 22 (ssh)
example.com 25 (smtp)
example.com 80 (http)
example.com 443 (https)
example.com 2222 (EtherNet-IP-1)
example.com 9081 (cisco-aqos)

~/workspace/scan-ports   7s
❯
```

* [Download binaries](../../releases)
