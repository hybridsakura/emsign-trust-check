import io


def patch(path, pairs):
    s = io.open(path, encoding="utf-8").read()
    for old, new in pairs:
        assert s.count(old) == 1, f"{path}: anchor not unique/found: {old[:60]}"
        s = s.replace(old, new)
    io.open(path, "w", encoding="utf-8", newline="\n").write(s)
    print("patched", path)


patch("public/index.html", [
    ('  <div id="offline-banner"', '  <!-- internet-only -->\n  <div id="offline-banner"'),
    ('margin:0 0 18px"></div>', 'margin:0 0 18px"></div>\n  <!-- /internet-only -->'),
    ('  <div class="card" id="check-card">', '  <!-- internet-only -->\n  <div class="card" id="check-card">'),
    ('<p style="margin:16px 0 0"><button id="rerun">Run check</button></p>\n  </div>',
     '<p style="margin:16px 0 0"><button id="rerun">Run check</button></p>\n  </div>\n  <!-- /internet-only -->'),
    ('<p style="margin:0">If every row above shows a timeout, this machine cannot reach the test domains and the live check is inconclusive. Use the bundled offline checker instead:</p>',
     '<!-- internet-only -->\n    <p style="margin:0">If every row above shows a timeout, this machine cannot reach the test domains and the live check is inconclusive. Use the bundled offline checker instead:</p>\n    <!-- /internet-only -->\n    <!-- lan-only -->\n    <p style="margin:0">This is the <strong>LAN edition</strong>: it never contacts the Internet. Run the bundled checker on the machine you want to inspect — both scripts read the local trust store and installed browser versions only.</p>\n    <!-- /lan-only -->'),
    ('<script>\n// Twelve test hosts', '<!-- internet-only -->\n<script>\n// Twelve test hosts'),
    ('\n// Browser info', '\n</script>\n<!-- /internet-only -->\n\n<script>\n// Browser info'),
])

patch("public/zh.html", [
    ('  <div id="offline-banner"', '  <!-- internet-only -->\n  <div id="offline-banner"'),
    ('margin:0 0 18px"></div>', 'margin:0 0 18px"></div>\n  <!-- /internet-only -->'),
    ('  <div class="card" id="check-card">', '  <!-- internet-only -->\n  <div class="card" id="check-card">'),
    ('<p style="margin:16px 0 0"><button id="rerun">开始检测</button></p>\n  </div>',
     '<p style="margin:16px 0 0"><button id="rerun">开始检测</button></p>\n  </div>\n  <!-- /internet-only -->'),
    ('<p style="margin:0">如果上面所有项目都显示"超时/无法连接"，说明本机无法访问外网测试域名，在线检测不可用。请使用配套的 PowerShell 离线检测脚本 <code>Check-EmSignTrust.ps1</code>，它通过以下方式判断：</p>',
     '<!-- internet-only -->\n    <p style="margin:0">如果上面所有项目都显示"超时/无法连接"，说明本机无法访问外网测试域名，在线检测不可用。请使用配套的 PowerShell 离线检测脚本 <code>Check-EmSignTrust.ps1</code>，它通过以下方式判断：</p>\n    <!-- /internet-only -->\n    <!-- lan-only -->\n    <p style="margin:0">本版本为<strong>内网版</strong>：页面不会发起任何外部网络请求。请把附带的脚本拷到需要检测的机器上运行——它们只读取本机信任库与已安装浏览器版本。</p>\n    <!-- /lan-only -->'),
    ('<script>\n// 十二个测试站点', '<!-- internet-only -->\n<script>\n// 十二个测试站点'),
    ('\n// 浏览器信息', '\n</script>\n<!-- /internet-only -->\n\n<script>\n// 浏览器信息'),
])
