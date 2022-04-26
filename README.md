# 命令

```
cargo run --example client
cargo run --example server
```

## local

本地解析sock5第一步 认证用户名，加密，与远程服务器建立连接，椭圆曲线加密`x25519-dalek`，获取对此加密密钥，把剩下的tcp流，对此加密转发到远程服务器。


## server

对称解密，解析sock5第二步，解析代理请求的远程服务器地址类型，DOMAINNAME，IP。建立连接，返回数据。





