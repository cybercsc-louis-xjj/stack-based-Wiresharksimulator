# 真实数据分析

## 刺激战场(和平精英)

采集工具：wireshark

平台：**iOS14.4、Android 7.0(Meizu M5 Note)**

### iOS14.4:

#### 采集方法和过程：

在PC端用wireshark对开启热点的虚拟网卡进行捕获，获取iphone流量，**从打开应用开始，一直到进行并结束一场游戏，再退回主界面，都是流量采集的范围内。**

#### 分析：

整个行为可以分为四阶段：**进入应用->打开应用进入主界面->进行并结束游戏->返回主界面**。通过初步观察可以发现，各个阶段主要产生的流量分别为：

**https->http->https->https:**

<img src="./image/phase1.jpg" alt="phase1" style="zoom: 40%;" />

<img src="./image/phase2.jpg" alt="phase2" style="zoom:40%;" />

<img src="./image/phase3.jpg" alt="phase3" style="zoom:40%;" />

<img src="./image/phase4.jpg" alt="phase4" style="zoom:40%;" />

我们先从加密协议信息入手。对于cilent hello提供的加密套件(cipher suites)，分析的价值不大，因为这个特征主要针对客户端，而在本次抓包实验中客户端只有一个。但是client hello中的SNI(Server Name Indication)包含域名信息，可以分析出一定的行为含义：

```
pkt2:server name:cloudctrl.gcloud.qq.com
pkt11:server name:cdn.wetest.qq.com
pkt12:server name:gpcloud.tgpa.qq.com
pkt27:server name:ip6.ssl.msdk.qq.com
pkt28:server name:ip6.ssl.msdk.qq.com
pkt57:server name:ip6.ssl.msdk.qq.com
pkt85:server name:ios.bugly.qq.com
pkt96:server name:down.anticheatexpert.com
pkt116:server name:ip6.ssl.msdk.qq.com
pkt123:server name:ip6.ssl.msdk.qq.com
pkt124:server name:ip6.ssl.msdk.qq.com
pkt127:server name:appsupport.qq.com
pkt146:server name:idcconfig.gcloud.qq.com
pkt153:server name:hpjy-op.tga.qq.com
pkt154:server name:szmg.qq.com
pkt204:server name:hpjy-op.tga.qq.com
pkt228:server name:szmg.qq.com
pkt300:server name:nggproxy.3g.qq.com
pkt422:server name:pubgmhdprobe.tgpa.qq.com
pkt1283:server name:ip6.ssl.msdk.qq.com
pkt1447:server name:priv.igame.qq.com
pkt1495:server name:down.pandora.qq.com
pkt1515:server name:priv.igame.qq.com
pkt1528:server name:c0d600848e9454720ee2a283bc400cf4.dlied1.cdntips.net
pkt9087:server name:game.gtimg.cn
pkt9114:server name:game.gtimg.cn
pkt9339:server name:appsupport.qq.com
pkt9386:server name:appsupport.qq.com
pkt9446:server name:idcconfig.gcloud.qq.com
pkt9464:server name:hpjy-op.tga.qq.com
pkt9492:server name:hpjy-op.tga.qq.com
pkt9507:server name:szmg.qq.com
pkt9529:server name:nggproxy.3g.qq.com
pkt9543:server name:ip6.ssl.msdk.qq.com
pkt9869:server name:pubgmhdprobe.tgpa.qq.com
pkt9884:server name:priv.igame.qq.com
```

分为四个阶段：

##### **1.进入应用阶段：pkt2-pkt300**+

**cloudctrl.gcloud.qq.com.** 腾讯游戏云服务的控制服务器
**cdn.wetest.qq.com.** 腾讯游戏开发的质量开放平台所提供的cdn加速服务
**gpcloud.tgpa.qq.com.**  腾讯游戏性能优化服务器, 在游戏登录加载、资源包解压更新时，通过软硬件的联合调度，加载更新速度更快，等待时间更短.
**ip6.ssl.msdk.qq.com.**  MSDK(腾讯游戏接入系统)的证书服务器,MSDK是腾讯互娱事业群为自研及第三方手游开发团队提供的，旨在帮助手游开发商快速接入腾讯个主要平台并上线运营的公共组件和服务库。
**ios.bugly.qq.com**. 腾讯针对iOS应用开发的异常监控和收集平台
**down.anticheatexpert.com** 反作弊插件(不是腾讯平台专有的)
**appsupport.qq.com** 猜测是游戏应用的其他一些支持程序
**idcconfig.gcloud.qq.com**. 腾讯数据中心，基于谷歌云服务器
**hpjy-op.tga.qq.com** hpjy是和平精英，根据查看Whois信息推测op可能是指OpenResty，是一个提供高并发响应和负载均衡服务的第三方模块；tga是腾讯电竞游戏平台。综合推测，这可能是腾讯电竞对和平精英推送的一些直播赛事接口，也可能是为游戏提供加速服务。
**szmg.qq.com**. 根据Whois信息，该域名的大部分IP位于深圳，推测szmg有两种可能：1.深圳广电的缩写，那么这个域名就是推送腾讯旗下的广播媒体产品，例如和深圳广电有合作的企鹅FM(感觉不太靠谱) 2.深圳mg动画，为游戏提供一些动画特效资源(也不太靠谱)
**nggproxy.3g.qq.com**. 手机腾讯的门户网，意义不明

**行为推测**：

从以上分析来看，在打开和平精英(刺激战场)过程中，首先**连接控制服务器**，然后**对游戏加载进行网络和数据解析两个方面的加速**，再然后**对异常信息和作弊外挂进行检测**。确认无异常后，**加载其他支持程序并连接数据中心**。最后**加载并连接其他服务**，进入主界面。



##### 2.打开应用进入主界面：pkt422-pkt9000左右

这里只分析之前未出现过的域名：

**ip6.ssl.msdk.qq.com.**  MSDK(腾讯游戏接入系统)的证书服务器
**pubgmhdprobe.tgpa.qq.com**. 针对和平精英游戏的性能优化(pubgmhd就是和平精英)
**priv.igame.qq.com**. 推测是腾讯游戏的隐私保护
**down.pandora.qq.com**.  Pandora,即腾讯潘多拉手游解决方案，负责腾讯游戏的社交、商城等整体生态运营。

事实上，进入主界面之后大部分连接都是通过http完成的

```
pkt1529:http
Host: 150.138.231.118
No field User-Agent
URL:/dlied1.qq.com/jdqssy/418021106/1235/dyncures/1.11.13.9151/418021106_1235_1.11.13.9151_20210120220930_681894274_dyncures.ifs?mkey=606b020c7c107065&f=850a&cip=124.16.86.144&proto=http&access_type=Wifi

pkt1530:http
Host: 42.81.119.65
No field User-Agent
URL:/dlied1.qq.com/jdqssy/418021106/1235/dyncures/1.11.13.9151/418021106_1235_1.11.13.9151_20210120220930_681894274_dyncures.ifs?mkey=606b020c7c107065&f=0f1e&cip=124.16.86.144&proto=http&access_type=Wifi

pkt1531:http
Host: 103.18.209.53
No field User-Agent
URL:/dlied1.qq.com/jdqssy/418021106/1235/dyncures/1.11.13.9151/418021106_1235_1.11.13.9151_20210120220930_681894274_dyncures.ifs?mkey=606b020c7c107065&f=0ae8&cip=124.16.86.144&proto=http&access_type=Wifi

pkt1600:http
Host: 150.138.231.107
No field User-Agent
URL:/dlied1.qq.com/jdqssy/418021106/1235/dyncures/1.11.13.9151/418021106_1235_1.11.13.9151_20210120220930_681894274_dyncures.ifs?mkey=606b020c7c107065&f=0c34&cip=124.16.86.144&proto=http&access_type=Wifi

pkt1601:http
Host: 42.81.119.54
No field User-Agent
URL:/dlied1.qq.com/jdqssy/418021106/1235/dyncures/1.11.13.9151/418021106_1235_1.11.13.9151_20210120220930_681894274_dyncures.ifs?mkey=606b020c7c107065&f=0f1e&cip=124.16.86.144&proto=http&access_type=Wifi

pkt2089:http
Host: 150.138.231.245
No field User-Agent
URL:/dlied1.qq.com/jdqssy/418021106/1235/dyncures/1.11.13.9151/418021106_1235_1.11.13.9151_20210120220930_681894274_dyncures.ifs?mkey=606b020c7c107065&f=0ef1&cip=124.16.86.144&proto=http&access_type=Wifi

pkt2301:http
Host: down.qq.com
No field User-Agent
URL:/jdqssy/418021106/1235/dyncures/1.11.13.9151/418021106_1235_1.11.13.9151_20210120220930_681894274_dyncures.ifs

pkt2302:http
Host: down.qq.com
No field User-Agent
URL:/jdqssy/418021106/1235/dyncures/1.11.13.9151/418021106_1235_1.11.13.9151_20210120220930_681894274_dyncures.ifs

pkt2312:http
Host: down.qq.com
No field User-Agent
URL:/jdqssy/418021106/1235/dyncures/1.11.13.9151/418021106_1235_1.11.13.9151_20210120220930_681894274_dyncures.ifs
```

并且这些http流量的时间密度很高，**大部分都包含带有dlied1的url，而pkt1528的sni中也包含dlied1**，并且还有一些哈希值前缀，所以pkt1528请求的这个服务器可能是分配给用户的一个前端资源cdn服务器，用于进入界面之后资源加载加速。

##### 3.游戏阶段：pkt9000左右-pkt9463

这个阶段的特点是流量不是很密集，主要是tls的continuation连接。

这里只列出之前未出现过的域名：

**game.gtimg.cn**. 腾讯的图片服务器，可能是加载游戏内的一些图片模型资源。

##### 4.退出游戏回到主界面：pkt9463+

游戏结束后，客户端**连接了一些在第一阶段连接过的服务器**，也就是断开游戏连接后要重新加载一些资源。

##### 5.其他信息

其实，在打开应用阶段，也存在少数http流量，并且可以从中找出设备信息：

```
pkt125:http
Host: 182.254.116.117
User-Agent: game=ShadowTrackerExtra, engine=UE4, version=4.18.1-0+++UE4+Release-4.18, platform=IOS, osver=14.4
URL:/d?dn=sqlobby.pg.qq.com.&clientip=1&ttl=1
```

可以看到平台为ios系统，版本为14.4

### Android

#### 采集方法和过程：

在安卓手机中(非模拟器)打开黑域，连接PC端的虚拟热点，在PC端用wireshark对开启热点的虚拟网卡进行捕获，**依然是从打开应用开始，一直到进行并结束一场游戏，再退回主界面。**

#### 分析：

从pcap文件的初步观察来看，整个流量的结构和在ios系统中的基本一致，也同样是四个阶段，各个阶段的流量分布也是**https->http->https->https（这里就不再放图片了）**

分析思路也还是针对SNI。

```
pkt6:server name:api.xunyou.mobi
pkt7:server name:api.xunyou.mobi
pkt31:server name:cloudctrl.gcloud.qq.com
pkt43:server name:cgi.connect.qq.com
pkt54:server name:ap6.ssl.msdk.qq.com
pkt66:server name:ap6.ssl.msdk.qq.com
pkt95:server name:ap6.ssl.msdk.qq.com
pkt132:server name:cdn.wetest.qq.com
pkt140:server name:gpcloud.tgpa.qq.com
pkt149:server name:mazu.m.qq.com
pkt165:server name:down.anticheatexpert.com
pkt175:server name:down.anticheatexpert.com
pkt184:server name:down.anticheatexpert.com
pkt193:server name:down.anticheatexpert.com
pkt213:server name:ap6.ssl.msdk.qq.com
pkt223:server name:ap6.ssl.msdk.qq.com
pkt224:server name:ap6.ssl.msdk.qq.com
pkt263:server name:idcconfig.gcloud.qq.com
pkt280:server name:hpjy-op.tga.qq.com
pkt292:server name:hpjy-op.tga.qq.com
pkt301:server name:report.tga.qq.com
pkt310:server name:report.tga.qq.com
pkt318:server name:appsupport.qq.com
pkt395:server name:nggproxy.3g.qq.com
pkt616:server name:api.xunyou.mobi
pkt859:server name:api.xunyou.mobi
pkt2652:server name:game.gtimg.cn
pkt2904:server name:idcconfig.gcloud.qq.com
pkt2928:server name:mazu.m.qq.com
pkt2945:server name:mazu.m.qq.com
pkt2960:server name:mazu.m.qq.com
pkt2978:server name:lbs.map.qq.com
pkt2989:server name:ssc-api.banqumusic.com
pkt2999:server name:api.meizu.com
pkt3017:server name:uxip.meizu.com
pkt3123:server name:nggproxy.3g.qq.com
pkt3132:server name:gpcloud.tgpa.qq.com
pkt3999:server name:report.tga.qq.com
```

分为四个阶段:

##### 1.进入应用阶段：pkt6-pkt330左右

这个阶段包含的SNI几乎和在ios中的对应阶段完全相同，除了**api.xunyou.mobi**，很明显是迅游加速器的手游服务API，这**可能是由于安卓生态下的app从不同的应用市场下载后，自身会与不同的第三方游戏加速服务关联，而ios生态下没有第三方的接入**;以及**mazu.m.qq.com**,目前并不清楚该域名的含义。

该阶段也存在少量http信息：

```
pkt48:http
Host: 182.254.116.117
User-Agent: Dalvik/2.1.0 (Linux; U; Android 7.0; M5 Note Build/NRD90M)
URL:/d?dn=e4a30b77424e17d729ad13c95d360e83407d631405df3425&clientip=1&ttl=1&id=1

pkt127:http
Host: android.bugly.qq.com
User-Agent: Dalvik/2.1.0 (Linux; U; Android 7.0; M5 Note Build/NRD90M)
No field GET/

pkt211:http
Host: 182.254.116.117
User-Agent: Dalvik/2.1.0 (Linux; U; Android 7.0; M5 Note Build/NRD90M)
URL:/d?dn=e4a30b77424e17d729ad13c95d360e83407d631405df3425&clientip=1&ttl=1&id=1

pkt243:http
Host: 182.254.116.117
User-Agent: game=ShadowTrackerExtra, engine=UE4, version=4.18.1-0+++UE4+Release-4.18, platform=Android, osver=7.0
URL:/d?dn=sqlobby.pg.qq.com.&clientip=1&ttl=1

pkt334:http
Host: 182.254.116.117
User-Agent: game=ShadowTrackerExtra, engine=UE4, version=4.18.1-0+++UE4+Release-4.18, platform=Android, osver=7.0
URL:/d?dn=sqlobby.pg.qq.com.&clientip=1&ttl=1
```

可以看到相关的设备信息，**Android 7.0; M5 Note Build/NRD90M**
还有一个SNI中未出现过的域名**android.bugly.qq.com**，应该是和ios.bugly.qq.com一样的功能。

##### 2.打开应用进入主界面：pkt330-pkt2900左右

这个阶段主要流量也还是http,并且URL也和ios中的有一些重合，**只是在这个阶段的SNI中并没有包含dlied1**。同时也有一些新的SNI:
**ssc-api.banqumusic.com**. 似乎是版趣公司提供的第三方内容服务
**api.meizu.com**.魅族手机的服务API
**uxip.meizu.com**.魅族推荐平台
这其实说明在不同的安卓平台下，大多数应用内部都会存在一些各自平台的，以及一些第三方平台的服务(因为开启了黑域，所以必然只能是应用内部产生的)。

**剩下两个阶段的行为内容则几乎没有什么不同。**





## Line TV

采集工具：wireshark

平台：Android xiaomi hm1s (模拟器)

版本：**这里我们选择了两个版本分别抓包分析，即LineTV-tw + LineTV**

### LineTV-tw

#### 采集方法和过程：

在模拟器中开启黑域，运行LineTV-tw, 利用vps服务器,在服务器上进行翻墙流量捕获，捕获后传回pcap.
进行的行为是，**打开App->观看一个视频->关闭**

#### 分析

整体初步观察，发现和刺激战场不同，LineTV基本上全部是https流量:

<img src="D:\Behaviour Science\LineTVnohttp.jpg" alt="LineTVnohttp" style="zoom:50%;" />

如图所示，端口号为80的http流量很少。

所以这里主要对https的SNI进行分析：

```
pkt6:server name:graph.facebook.com
pkt8:server name:graph.facebook.com
pkt23:server name:global-nvapis.line.me
pkt38:server name:ace.line.me
pkt47:server name:open.e.kuaishou.com
pkt72:server name:ace.line.me
pkt107:server name:googleads.g.doubleclick.net
pkt156:server name:lan3rd.line.me
pkt174:server name:googleads.g.doubleclick.net
pkt185:server name:tv-img.pstatic.net
pkt193:server name:tv-img.pstatic.net
pkt262:server name:pubads.g.doubleclick.net
pkt277:server name:lh3.googleusercontent.com
pkt279:server name:lh5.googleusercontent.com
pkt281:server name:tpc.googlesyndication.com
pkt283:server name:app-measurement.com
pkt334:server name:ssl.google-analytics.com
pkt336:server name:pagead2.googleadservices.com
pkt442:server name:pubads.g.doubleclick.net
pkt481:server name:tv-line.pstatic.net
pkt524:server name:pagead2.googlesyndication.com
pkt640:server name:imasdk.googleapis.com
pkt642:server name:tv-line.pstatic.net
pkt759:server name:global-nvapis.line.me
pkt778:server name:global-nvapis.line.me
pkt1096:server name:nelo2-col.linecorp.com
pkt1436:server name:dc1-st.ksn.kaspersky-labs.com
```

**graph.facebook.com**. 脸书的图片API
**global-nvapis.line.me**. LineTV用于存储推流地址的站点
**ace.line.me**. 可能是line贴图接口
**open.e.kuaishou.com**. 快手视频API(不过我既没有看到快手的广告，也没有在模拟器里开快手，有些费解)
**googleads.g.doubleclick.net**. 谷歌广告流量
**lan3rd.line.me**. 未知
**tv-img.pstatic.net**. 一般用于加载LineTV缩略图
**pubads.g.doubleclick.net**. 同样是广告流量，但是这个相较于之前的那个更偏向于恶意刷流量。
**lh3.googleusercontent.com lh5.googleusercontent.com**. 谷歌用户照片共享接口
**tpc.googlesyndication.com**. 还是谷歌广告推荐流量
**app-measurement.com**. 谷歌的站点统计行为，也就是谷歌的Google Analytics服务,它会收集用户访问站点时产生的各种信息。
**ssl.google-analytics.com** 加了安全措施的Google Analytics
**pagead2.googleadservices.com   pubads.g.doubleclick.net    pagead2.googlesyndication.com** 还是广告
**imasdk.googleapis.com**. 谷歌广告安全开发工具
**nelo2-col.linecorp.com**. 似乎是LineTV母公司Line的一个接口，可能是Line账号登录的接口
**dc1-st.ksn.kaspersky-labs.com**. 卡巴斯基站点(更加费解了)

仅从tls的角度分析，无法看出太多有用的信息。除了打开视频时对视频流地址进行了连接，其他的大多都是google的广告会话以及站点信息收集行为。不过这也说明，流量中还存在很多LineTV自定义的私有协议，这些流量包含了真正的行为信息。

**而实际情况也是这样，流量包中也存在很多ipv6的流量：**

![LineTV ipv6](.\LineTV ipv6.jpg)

暂时还无法获取这些私有协议的模式。

### LineTV

#### 采集方法和过程：

在模拟器中开启黑域，运行LineTV, 利用vps服务器,在服务器上进行翻墙流量捕获，捕获后传回pcap.
进行的行为是，**打开LineTV->观看一个视频->关闭**

#### 分析

在LineTV中，**获取的流量完全不包含ipv6，这一点目前也没有分析出为什么**。

接下来依然是对SNI的分析：

```
pkt17:server name:graph.facebook.com
pkt28:server name:graph.facebook.com
pkt62:server name:global-nvapis.line.me
pkt86:server name:ace.line.me
pkt102:server name:ace.line.me
pkt120:server name:global-nvapis.line.me
pkt182:server name:lan3rd.line.me
pkt212:server name:tv-img.pstatic.net
pkt220:server name:tv-img.pstatic.net
pkt931:server name:tv-line.pstatic.net
pkt989:server name:tv-line.pstatic.net
pkt1016:server name:pubads.g.doubleclick.net
pkt1025:server name:pubads.g.doubleclick.net
pkt1034:server name:pubads.g.doubleclick.net
pkt1141:server name:s0.2mdn.net
pkt1163:server name:s0.2mdn.net
pkt1167:server name:pagead2.googlesyndication.com
pkt1173:server name:pagead2.googlesyndication.com
pkt1362:server name:s0.2mdn.net
pkt1457:server name:imasdk.googleapis.com
pkt1488:server name:lh3.googleusercontent.com
pkt1524:server name:lh3.googleusercontent.com
pkt1642:server name:googleads.g.doubleclick.net
pkt1658:server name:googleads.g.doubleclick.net
pkt1661:server name:pagead2.googleadservices.com
pkt1766:server name:csi.gstatic.com
pkt1812:server name:r3---sn-npoeenee.googlevideo.com
pkt1926:server name:tv-line.pstatic.net
pkt1937:server name:ad.doubleclick.net
pkt1955:server name:ade.googlesyndication.com
pkt1956:server name:ade.googlesyndication.com
pkt2736:server name:nelo2-col.linecorp.com
pkt3995:server name:ace.line.me
pkt4320:server name:lan3rd.line.me
```

可以看到，出现了很多LineTV中同样出现过的服务器，例如graph.facebook.com，ace.line.me，tv-img.pstatic.net，以及最关键的用于视频流传输的global-nvapis.line.me。当然，也少不了谷歌的广告推送。

不过其中还包含了一些新的域名：
**tv-line.pstatic.net**. 和**tv-img.pstatic.net**类似，LineTV的图片缓存服务器
**s0.2mdn.net**. 依然是广告网络
**r3---sn-npoeenee.googlevideo.com**.谷歌视频API，怀疑依然是谷歌的广告

总体分析下来，面向台湾地区的LineTV-tw和它的主体部分LineTV的流量行为没有太大差别，**除了前者存在较多的ipv6流量，而后者几乎没有**。

