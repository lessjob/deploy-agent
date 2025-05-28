### 1. 快速开始
修改配置文件 config.yml : 
```yaml
#  服务端口
port: 5002
#  IP白名单
ip_whitelist:
  - "127.0.0.1"
  - "192.168.1.100"
  - "::1"
# 工作目录
workspace: "~/code/go/aiwork/FileDeploy/workspace/"
# 文件上传限制(MB)
max_upload_size: 500
# API密钥
api_key: "123456!"
# 请求速率限制(次/分钟)
rate_limit: 60
```
### 2. 运行服务
```bash
go run deploy_agent.go config.yml
```

