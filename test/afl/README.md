
# 用 American Fuzzy Lop（AFL）对 fwknop 做模糊测试

（本文件为 Zurker fork 翻译维护的中文译本；英文原文见 README.en.md。）

## 快速上手

开始用 AFL 对 fwknop 做模糊测试：

    $ cd fwknop.git/test/afl/
    $ ./compile/afl-compile.sh
    $ ./fuzzing-wrappers/spa-pkts.sh

模糊测试结果会放在 fuzzing-output/server-conf.out/。更多信息请继续阅读。

## 简介

fwknop 项目支持多种模糊测试策略，其中最重要的之一是使用 Michal Zalewski
编写的「American Fuzzy Lop」（AFL）模糊器（见
[http://lcamtuf.coredump.cx/afl/]）。由于 AFL 并非为处理加密方案而设计
（详见 AFL 源码自带的 README），fwknop 的 autoconf configure 脚本提供了
专门的 *--enable-afl-fuzzing* 命令行开关。该参数允许在经由 stdin 向
fwknopd 喂入 SPA 报文数据时绕过加密与 base64 编码。正是这一特性使 AFL
模糊测试成为可能，其作用与 AFL 源码中自带的 *libpng-nocrc.patch* 补丁
类似。在 fwknop 中启用该功能的对应提交是
aaa44656bcfcb705d80768a7b9aa0d45a0e55e21
（见：[https://github.com/mrash/fwknop/commit/aaa44656bcfcb705d80768a7b9aa0d45a0e55e21]）

## AFL 包装脚本

顶层目录包含若干辅助脚本，方便用 AFL 对 fwknop 做模糊测试。这里假设 AFL
已安装并在 PATH 中。本目录中的文件组织如下：

 * *fuzzing-wrappers/*

  包含对 fwknop 运行 AFL 的包装脚本的目录。与 AFL 的所有交互都应通过
  这些脚本进行，并且应当在 test/afl/ 目录中执行，例如
  *./fuzzing-wrappers/client-rc.sh*。

  fwknop 中有四个区域被模糊测试：
    1. SPA 报文编码/解码（*./fuzzing-wrappers/spa-pkts.sh*）
    2. 服务端 access.conf 解析（*./fuzzing-wrappers/server-access.sh*）
    3. 服务端 fwknopd.conf 解析（*./fuzzing-wrappers/server-conf.sh*）
    4. 客户端 fwknoprc 文件解析（*./fuzzing-wrappers/client-rc.sh*）

 * *fuzzing-wrappers/helpers/*

  辅助脚本目录，供模糊测试包装脚本使用，以确保 fwknop 已为 AFL 支持正确
  编译并就绪，可以开始模糊测试循环。

 * *test-cases/*

  包装脚本所使用的 AFL 测试用例目录。

 * *compile/*

  编译脚本目录，用于确保 fwknop 在 afl-gcc 之下编译。

 * *fuzzing-output/*

  AFL 模糊测试循环产生的结果目录。

## 完整示例

要对 SPA 报文编码/解码例程做模糊测试，运行
*fuzzing-wrappers/spa-pkts.sh* 脚本即可开始。这里假设 fwknop 已用
*compile/afl-compile.sh* 脚本编译了 AFL 支持：

    $ ./fuzzing-wrappers/spa-pkts.sh
    ...
    + LD_LIBRARY_PATH=../../lib/.libs afl-fuzz -t 1000 -i test-cases/spa-pkts -o fuzzing-output/spa-pkts.out ../../server/.libs/fwknopd -c ../conf/default_fwknopd.conf -a ../conf/default_access.conf -A -f -t
    afl-fuzz 0.64b (Nov 22 2014 13:04:11) by <lcamtuf@google.com>
    [+] You have 1 CPU cores and 2 runnable tasks (utilization: 200%).
    [*] Checking core_pattern...
    [*] Setting up output directories...
    [+] Output directory exists but deemed OK to reuse.
    [*] Deleting old session data...
    [+] Output dir cleanup successful.
    [*] Scanning 'test-cases/spa-pkts'...
    [*] Creating hard links for all input files...
    [*] Validating target binary...
    [*] Attempting dry run with 'id:000000,orig:spa.start'...
    [*] Spinning up the fork server...
    [+] All right - fork server is up.
    ...

随后会显示大家熟悉的 AFL 状态界面：

![alt text][AFL-status-screen]

[AFL-status-screen]: https://github.com/mrash/fwknop/raw/master/test/afl/doc/AFL_status_screen.png "AFL Fuzzing SPA Packets"

## SPA 报文辅助脚本

下面是一个示例：当 fwknopd 以 AFL 支持编译后，经由其 stdin 以未编码/
未加密的形式提供一个伪 SPA 报文时所产生的输出。这里使用
*fwknopd-stdin-test.sh* 辅助脚本：

    $ ./fuzzing-wrappers/helpers/fwknopd-stdin-test.sh
    + SPA_PKT=1716411011200157:root:1397329899:2.0.1:1:127.0.0.2,tcp/22:AAAAA
    + LD_LIBRARY_PATH=../../lib/.libs ../../server/.libs/fwknopd -c ../conf/default_fwknopd.conf -a ../conf/default_access.conf -A -f -t
    + echo -n 1716411011200157:root:1397329899:2.0.1:1:127.0.0.2,tcp/22:AAAAA
    Warning: REQUIRE_SOURCE_ADDRESS not enabled for access stanza source: 'ANY'
    SPA Field Values:
    =================
       Random Value: 1716411011200157
           Username: root
          Timestamp: 1397329899
        FKO Version: 2.0.1
       Message Type: 1 (Access msg)
     Message String: 127.0.0.2,tcp/22
         Nat Access: <NULL>
        Server Auth: <NULL>
     Client Timeout: 0
        Digest Type: 3 (SHA256)
          HMAC Type: 0 (None)
    Encryption Type: 1 (Rijndael)
    Encryption Mode: 2 (CBC)
       Encoded Data: 1716411011200157:root:1397329899:2.0.1:1:127.0.0.2,tcp/22
    SPA Data Digest: AAAAA
               HMAC: <NULL>
     Final SPA Data: 200157:root:1397329899:2.0.1:1:127.0.0.2,tcp/22:AAAAA

    SPA packet decode: Success
