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

### 3. 部署文件

#### 请求头(header):
- X-API-Key 授权请求头 需要和 config.yml 中的 api_key 一致
#### 请求参数(body):
- targetPath 文件部署目标路径 (如果目标已经存在会自动备份)
- isAutoUnzip 是否自动解压 (仅支持zip 文件)
- unzipPath 解压目标路径 (如果目标已经存在会自动备份)
- file 文件
```bash
# curl示例
curl -X POST \
  -H "X-API-Key: 123456!" \
  -F "targetPath=test/dist.zip" \
  -F "isAutoUnzip=true" \
  -F "unzipPath=test/dist/" \
  -F "file=@~/Downloads/dist.zip" \
  http://192.168.1.96:5002/deploy
```
