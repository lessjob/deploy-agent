# curl -X POST \
#   -H "X-API-Key: 123456!" \
#   -F "targetPath=test/123.jar" \
#   -F "file=@/Users/liuwei/Downloads/jacoco-0.8.13/lib/jacocoagent.jar" \
#   http://192.168.1.96:5002/deploy


curl -X POST \
  -H "X-API-Key: 123456!" \
  -F "targetPath=test/dist.zip" \
  -F "isAutoUnzip=true" \
  -F "unzipPath=test/dist222/" \
  -F "file=@~/Downloads/dist-1/归档2.zip" \
  http://192.168.1.96:5002/deploy

# curl -X POST \
#   -H "X-API-Key: 123456!" \
#   -F "targetPath=test/dist.zip" \
#   -F "isAutoUnzip=true" \
#   -F "unzipPath=test/dist222/" \
#   -F "file=@/Users/liuwei/Downloads/dist-1/归档2.zip" \
#   http://localhost:5002/deploy