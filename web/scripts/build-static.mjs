// 跨平台静态导出：`npm run build:static` 的 Windows 兼容版。
//
// 原来的写法是 `NEXT_EXPORT=1 next build`（POSIX 环境变量前缀）。Windows 上 npm 用 cmd.exe
// 执行脚本，cmd 不认识 `VAR=value cmd` 这种语法，直接报
// "'NEXT_EXPORT' 不是内部或外部命令" —— 也就是说在 Windows 上 build.sh 必然失败。
// 这里改成 Node 脚本：自己设环境变量再拉起 next，三个平台同一条路径。
import { spawn } from "node:child_process";

const isWin = process.platform === "win32";
const child = spawn(isWin ? "npx.cmd" : "npx", ["next", "build"], {
  stdio: "inherit",
  env: { ...process.env, NEXT_EXPORT: "1" },
  // Windows 上 .cmd 需要 shell 才能被解析；POSIX 上不开 shell，避免空格/引号被再次解释。
  shell: isWin,
});

child.on("exit", (code, signal) => {
  if (signal) {
    console.error(`[build:static] 被信号 ${signal} 终止`);
    process.exit(1);
  }
  process.exit(code ?? 1);
});
