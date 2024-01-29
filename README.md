工具借鉴homeassistant插件方式，通过调用手机厂商的查找接口/模拟登录等方式来获取定位信息，部分品牌手机由于数据加密无法获取定位信息

## 操作步骤
### 青龙中部署定时定位程序
1. 安装依赖：
```
apk add chromium
apk add chromium-chromedriver

pip3 install selenium
pip3 install flask
```

2. 代码目录中location.py文件放在青龙中定时执行
- 用于定时获取配置手机的定位
- 脚本执行示例：task python3 location.py -xp 138xxxxxxxx,88888888 -hp 183xxxxxxxx,88888888 -xp 158xxxxxxxx,8888888 -d /ql/data/location
```
root@f0e1cf3bc37a:/ql/data/scripts $ python3 location.py -h
usage: location.py [-h] [-d DIRECTORY] [-xp XIAOMI_PHONE] [-hp HUAWEI_PHONE] [-rp REALME_PHONE]

Arguments for start phone location system

options:
  -h, --help            show this help message and exit
  -d DIRECTORY, --directory DIRECTORY
                        set data directory
  -xp XIAOMI_PHONE, --xiaomi-phone XIAOMI_PHONE
                        location xiaomi phones
  -hp HUAWEI_PHONE, --huawei-phone HUAWEI_PHONE
                        location huawei phones
  -rp REALME_PHONE, --realme-phone REALME_PHONE
                        location realme phones
```

> 当前只支持小米和华为手机
> 青龙中数据保存在/ql/data/location目录下，其他任意支持定时任务的平台都可以，当前也可以用crontab工具

### 启动web服务
在和青龙相同服务端中运行location web容器（为了读取青龙脚本获取的定位数据），其中数据目录使用青龙数据目录下的location目录
location web镜像仅仅用来显示定时获取的位置

    docker run -d --restart=always -v /ql/data/location:/etc/location -p 50073:80 --name phone_location xxx/location:latest

## location web容器build
- location_web.py文件中需要配置默认的用户名和密码（admin/88888888）,自行修改或者优化成读取配置或者环境变量
- location_web.py文件中需要配置默认手机号，作为居中显示，自行修改或者优化成读取配置或者环境变量

```
docker build -o xxx/location:latest
```


