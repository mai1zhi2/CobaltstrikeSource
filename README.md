# CobaltstrikeSource
Cobaltstrike4.1 Source
这是反编译后的Cobaltstrike4.1源码，修改了一点反编译后的bug,teamserver与agressor均能正常调试使用,若想自己修改调试那个文件只需把该文件复制到src下即可。

这是魔改Cobaltstrike4.1系列的帖子，若有错误请指出，谢谢：

魔改CobaltStrike：二开及后门生成分析：https://www.52pojie.cn/thread-1371712-1-1.html

魔改CobaltStrike：免杀就像便秘一样：https://www.52pojie.cn/thread-1396671-1-1.html

CobaltStrike4.0 远控stage分析:https://www.52pojie.cn/thread-1334525-1-1.html

魔改CobaltStrike：协议全剖析：https://www.52pojie.cn/thread-1426936-1-1.html

魔改CobaltStrike:上线就跟回家一样：https://www.52pojie.cn/thread-1401826-1-1.html


teamserver端的调试配置看图片，其中地址和端口根据实际填写。
详细参数如下，-Djavax.net.ssl.keyStore的目录根据实际的填写：
-XX:ParallelGCThreads=4 -Xms512m -Xmx1024m -Dcobaltstrike.server_port=50050 -Djavax.net.ssl.keyStore=C:/Users/kent/Downloads/CobaltStrike/cobaltstrike.store -Djavax.net.ssl.keyStorePassword=123456 -server -XX:+AggressiveHeap -XX:+UseParallelGC
