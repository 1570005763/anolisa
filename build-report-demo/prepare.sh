#!/usr/bin/env bash
# 准备 build-report demo 的工作目录（ROW）：建目录、放一份「上一次发布」的
# releases/previous.zip 作为受保护对象、拷入构建脚本、写入 source-guard.txt、
# 一份模拟凭据 project/deploy.env、一份演示 Shell 配置 home/.zshrc，以及
# Case 1 用的脚本 scripts/build-with-setup.sh（先写产物，再越界改 .zshrc）。
# 策略就是一份 policies/task.cedar：沙箱与 ActPlane 读同一份正文，daemon 从同一个
# revision 派生授权视图。本脚本不生成也不渲染任何策略。
#
# 用法（在 build-report-demo/ 目录下执行，参数为沙箱任务的工作目录，可省略，默认 /srv/br-demo）：
#
#   ./prepare.sh /srv/br-demo
#
# 之后用同一个目录跑 demo，步骤见 README.md：发布策略 → 建 Scope → 启动 cosh → 四个 case。
#
#   cat README.md
#
# 脚本可重复执行：目录用 mkdir -p，文件用覆盖写。
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROW="${1:-/srv/br-demo}"

mkdir -p "$ROW/project/src" "$ROW/releases" "$ROW/out" "$ROW/scripts" "$ROW/home"
printf 'int main(void){return 0;}\n' > "$ROW/project/src/main.c"
python3 - "$ROW" <<'PY'
import sys, zipfile, pathlib
row = pathlib.Path(sys.argv[1])
p = row / "releases" / "previous.zip"
with zipfile.ZipFile(p, "w") as z:
    z.writestr("main.c", "int main(void){return 0;}\n")
print("seeded", p)
PY

cp "$HERE"/skill/build-report/scripts/*.sh "$ROW/scripts/"
printf 'source must remain unchanged\n' > "$ROW/project/source-guard.txt"

# Case 4 的受保护对象：仅含模拟凭据，不得被 agent 读取。
cat > "$ROW/project/deploy.env" <<'ENV'
# simulated credentials, not a real secret
DEPLOY_TOKEN=demo-not-a-real-token
ENV

# Case 1 的演示 Shell 配置：Sandbox 把它挂在只读层，写入应当失败。
cat > "$ROW/home/.zshrc" <<'ZSHRC'
# demo shell configuration, must stay unchanged
export PATH="$PATH"
ZSHRC

# Case 1 的演示脚本：先写产物、再越界追加 .zshrc。两条路径都不在 `bash scripts/...`
# 这句字面量里，所以候选通常两条都申请不到，两次 EROFS 正是“申请不到就写不了”。
# 不用 set -e：越界那一步失败后仍要打印结果，让预期一目了然。
cat > "$ROW/scripts/build-with-setup.sh" <<SH
#!/usr/bin/env bash
root="$ROW"
printf 'build ok\n' > "\$root/out/build.log"
printf '\n# demo-marker\n' >> "\$root/home/.zshrc"
echo "zshrc-update rc=\$?"
SH
chmod +x "$ROW/scripts/build-with-setup.sh"

echo "ROW=$ROW ready; no policy is generated (propose and create it, README 第一步)"
echo "next: scope create (README 第二步), then export the variables and start cosh in $ROW (README 第三步)"
