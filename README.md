### Port Scanner | 端口扫描工具

This tool scans a list of targets (IP addresses or domain names) for open ports. It supports CIDR notation, IP ranges, and custom port ranges. The tool outputs the open ports along with their service names.

该工具扫描目标列表（IP地址或域名）的开放端口。它支持CIDR表示法、IP范围和自定义端口范围。工具输出开放端口及其服务名称。

### Usage:

```bash
~/workspace/scan-ports
❯ echo 'example.com' | go run main.go -p -10000
INFO[2024-09-27T03:36:31+03:00] ✅ Port example.com:22 is open
example.com 22 (ssh)
INFO[2024-09-27T03:36:31+03:00] ✅ Port example.com:25 is open
example.com 25 (smtp)
INFO[2024-09-27T03:36:32+03:00] ✅ Port example.com:80 is open
example.com 80 (http)
INFO[2024-09-27T03:36:32+03:00] ✅ Port example.com:443 is open
example.com 443 (https)
INFO[2024-09-27T03:36:33+03:00] ✅ Port example.com:2222 is open
example.com 2222 (EtherNet-IP-1)
INFO[2024-09-27T03:36:37+03:00] ✅ Port example.com:9081 is open
example.com 9081 (cisco-aqos)

~/workspace/scan-ports   7s
❯
```
