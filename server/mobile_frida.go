package server

// Frida 脚本模板库。刻意做成「代码里固定的几份模板」而不是让模型自由生成 JS：
//  1. 授权链校验的是 op（hook / frida），不是脚本内容。若脚本可由模型任意写，
//     一次 hook 就能在已授权设备上做授权范围之外的事，硬闸会被架空；
//  2. 固定模板能审计、能复刻、能在不同 ROM 上给出稳定的降级行为；
//  3. 输出刻意只记录「发生了什么」（算法名、URL、路径、长度），不打印请求头、
//     请求体、密钥明文或 Cookie —— 与证据脱敏规则同源，从源头少产敏感数据。
//
// 脚本只是模板文件：应用容器不内置 frida 二进制，实际注入由沙箱容器里的
// frida-tools（mobile-dynamic 预置）执行。工具返回脚本路径与可直接复制的命令，
// 不谎称平台自己在跑 frida。

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// mobileFridaScripts 是闭集模板。key 即 mobile_hook 的 script 参数。
var mobileFridaScripts = map[string]string{
	"ssl_pinning_bypass": `// [praetor] 通用 Java 层证书绑定绕过（仅用于已授权的测试设备）
Java.perform(function () {
  var log = function (m) { console.log('[praetor] ' + m); };
  try {
    var X509 = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
      name: 'org.praetor.TrustAll', implements: [X509],
      methods: {
        checkClientTrusted: function () {}, checkServerTrusted: function () {},
        getAcceptedIssuers: function () { return []; }
      }
    });
    SSLContext.init.overload('[Ljavax.net.ssl.KeyManager;', '[Ljavax.net.ssl.TrustManager;', 'java.security.SecureRandom')
      .implementation = function (km, tm, sr) {
        log('SSLContext.init -> 替换 TrustManager');
        return this.init(km, [TrustManager.$new()], sr);
      };
  } catch (e) { log('TrustManager hook 跳过: ' + e); }
  try {
    var Pinner = Java.use('okhttp3.CertificatePinner');
    Pinner.check.overload('java.lang.String', 'java.util.List').implementation = function (host, pins) {
      log('CertificatePinner.check 放行 host=' + host + ' pins=' + pins.size());
      return;
    };
  } catch (e) { log('OkHttp CertificatePinner 未使用或版本不同'); }
});
`,
	"root_detection_bypass": `// [praetor] 常见 root 检测点绕过（仅记录命中，不改系统状态）
Java.perform(function () {
  var log = function (m) { console.log('[praetor] ' + m); };
  try {
    var File = Java.use('java.io.File');
    File.exists.implementation = function () {
      var p = this.getAbsolutePath();
      if (/su$|busybox|magisk|Superuser|daemonsu/.test(p)) {
        log('root 检测点命中: ' + p + ' -> 返回 false');
        return false;
      }
      return this.exists();
    };
  } catch (e) { log('File.exists hook 跳过: ' + e); }
  try {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function (cmd) {
      if (/^\s*su\b|\bwhich su\b/.test(cmd)) { log('root 检测命令拦截: ' + cmd); throw Java.use('java.io.IOException').$new('blocked'); }
      return this.exec(cmd);
    };
  } catch (e) { log('Runtime.exec hook 跳过: ' + e); }
});
`,
	"crypto_trace": `// [praetor] 加密调用追踪：只打算法/长度，不打密钥与明文
Java.perform(function () {
  var log = function (m) { console.log('[praetor] ' + m); };
  try {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function (t) {
      log('Cipher.getInstance(' + t + ')'); return this.getInstance(t);
    };
    Cipher.doFinal.overload('[B').implementation = function (input) {
      log('Cipher.doFinal algorithm=' + this.getAlgorithm() + ' input_len=' + input.length);
      return this.doFinal(input);
    };
  } catch (e) { log('Cipher hook 跳过: ' + e); }
  try {
    var MD = Java.use('java.security.MessageDigest');
    MD.digest.overload('[B').implementation = function (input) {
      log('MessageDigest.digest algorithm=' + this.getAlgorithm() + ' input_len=' + input.length);
      return this.digest(input);
    };
  } catch (e) { log('MessageDigest hook 跳过: ' + e); }
});
`,
	"http_trace": `// [praetor] 网络请求追踪：只打方法与 URL，不打请求头/请求体/Cookie
Java.perform(function () {
  var log = function (m) { console.log('[praetor] ' + m); };
  try {
    var URL = Java.use('java.net.URL');
    URL.openConnection.overload().implementation = function () {
      log('URL.openConnection ' + this.getProtocol() + '://' + this.getHost() + this.getFile());
      return this.openConnection();
    };
  } catch (e) { log('URL hook 跳过: ' + e); }
  try {
    var Request = Java.use('okhttp3.Request$Builder');
    Request.url.overload('java.lang.String').implementation = function (u) {
      log('OkHttp Request.Builder.url ' + u); return this.url(u);
    };
  } catch (e) { log('OkHttp 未使用或版本不同'); }
});
`,
	"storage_trace": `// [praetor] 本地存储写入追踪：只打路径与键名，不打值
Java.perform(function () {
  var log = function (m) { console.log('[praetor] ' + m); };
  try {
    var Editor = Java.use('android.content.SharedPreferences$Editor');
    Editor.putString.overload('java.lang.String', 'java.lang.String').implementation = function (k, v) {
      log('SharedPreferences.putString key=' + k + ' value_len=' + (v === null ? 0 : v.length));
      return this.putString(k, v);
    };
  } catch (e) { log('SharedPreferences hook 跳过: ' + e); }
  try {
    var File = Java.use('java.io.File');
    File.$init.overload('java.lang.String').implementation = function (p) {
      if (/shared_prefs|databases|\.db$/.test(p)) { log('本地数据文件打开: ' + p); }
      return this.$init(p);
    };
  } catch (e) { log('File hook 跳过: ' + e); }
});
`,
}

func mobileFridaScriptNames() []string {
	out := make([]string, 0, len(mobileFridaScripts))
	for k := range mobileFridaScripts {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// saveMobileFridaScript 把固定模板写到任务工作区，返回容器可见路径。
// 只接受白名单 key，模型无法写入任意 JS 内容。
func (s *Server) saveMobileFridaScript(taskID int64, name string) (string, error) {
	body, ok := mobileFridaScripts[strings.TrimSpace(name)]
	if !ok {
		return "", fmt.Errorf("未知 frida 模板 %q（可用：%s）", name, strings.Join(mobileFridaScriptNames(), " / "))
	}
	dir, err := s.mobileEvidenceDir(taskID)
	if err != nil {
		return "", err
	}
	fridaDir := filepath.Join(dir, "frida")
	if err := os.MkdirAll(fridaDir, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(fridaDir, name+".js")
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		return "", err
	}
	return "/work/mobile/frida/" + name + ".js", nil
}

// mobileFridaCommand 生成在沙箱容器里执行的命令（供 agent 用 Bash 调用，
// 那条 Bash 同样会过 guard 的 frida/hook 授权校验）。
func mobileFridaCommand(scriptPath, pkg, mode string) string {
	cmd := "frida -U"
	if pkg != "" {
		cmd += " -f " + pkg
	}
	cmd += " -l " + scriptPath + " --no-pause"
	if mode == "spawn" {
		cmd += " -o /work/mobile/frida-output.log"
	}
	return cmd
}

// mobileFridaScriptList 是给 mobile_frida 的只读 list 动作用的说明文本。
func mobileFridaScriptList() string {
	var b strings.Builder
	b.WriteString("可用 frida 模板（闭集，平台只提供这些脚本）：\n")
	for i, name := range mobileFridaScriptNames() {
		b.WriteString(strconv.Itoa(i+1) + ". " + name + "\n")
	}
	b.WriteString("\n脚本输出统一带 [praetor] 前缀，可用 mobile_logcat 的 filter 过滤。" +
		"\n脚本不会打印 Cookie/Token/完整报文/密钥明文；如设备侧自行打印，证据落盘仍会二次脱敏。")
	return b.String()
}
