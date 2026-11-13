#!/usr/bin/env bash
# 三组件 RPM 重建流水线：卸载 -> 编译 -> 安装 -> 启动并检查服务。
#
# 覆盖组件（入参，可任意组合）：
#   agentseccore | agent-sec-core   包：agent-sec-core / agent-sec-plugins / agent-sec-skills
#   sight       | agentsight        包：agentsight-core / agentsight / agentsight-plugins
#   cosh        | cosh-ng           包：cosh-ng
#   all                             三个组件按上面的顺序全部执行
#
# 用法（脚本自行定位仓库根，可在任意目录执行）：
#   ./rpm-cycle.sh agentseccore sight cosh
#   ./rpm-cycle.sh all
#   ./rpm-cycle.sh cosh --help
#
# 每个组件固定四步，任一步失败只记录并继续下一个组件，最后统一汇总：
#   1. stop  停止并 disable 该组件的 systemd 单元，再 dnf remove 对应 RPM
#   2. build 调用 scripts/rpm-build.sh 重建 RPM（全程 flock，禁止并发）
#   3. install 安装本次构建产出的 RPM（构建后按时间戳清单锁定，不装历史包）
#   4. start   enable --now 服务并带超时探活（unit / socket / HTTP）
#
# 产物只保留一份：构建成功后删除同组件的其他版本（RPMS 与 SRPMS），
# 安装后再确认系统上没有同名包的多版本共存。KEEP_ARTIFACTS=1 可关闭清理。
#
# 可覆盖的环境变量：
#   VERSION                 透传给 scripts/rpm-build.sh，覆盖 RPM 版本
#   CARGO_BUILD_JOBS        cosh-ng 构建并发（默认 4，规避 FatLTO 资源竞争）
#   COSH_GATEWAY_INSTANCE   cosh 网关实例名（默认 root）
#   COSH_GATEWAY_WORKSPACE  网关工作目录（默认 root 家目录）
#   AGENTSIGHT_HTTP_PORT    AgentSight server 探活端口（默认 7396）
#   RPM_CYCLE_LOG_DIR       日志目录（默认 /tmp/anolisa-rpm-cycle.XXXXXX）
#   KEEP_ARTIFACTS=1        保留历史版本产物（默认会清理，每个包只留一份）
#
# 退出码：0 全部成功；1 至少一个组件有步骤失败。
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(dirname "$HERE")"
RPM_BUILD="$ROOT/scripts/rpm-build.sh"
RPM_TOP="$ROOT/scripts/rpmbuild"
RPMS_X86="$RPM_TOP/RPMS/x86_64"
RPMS_NOARCH="$RPM_TOP/RPMS/noarch"
BUILD_LOCK="/var/lock/anolisa-rpm-cycle.lock"

COSH_INSTANCE="${COSH_GATEWAY_INSTANCE:-root}"
COSH_WORKSPACE="${COSH_GATEWAY_WORKSPACE:-/root}"
AGENTSIGHT_PORT="${AGENTSIGHT_HTTP_PORT:-7396}"
LOG_DIR="${RPM_CYCLE_LOG_DIR:-$(mktemp -d /tmp/anolisa-rpm-cycle.XXXXXX)}"
WAIT_SECONDS="${RPM_CYCLE_WAIT_SECONDS:-30}"

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; CYAN='\033[0;36m'; NC='\033[0m'
info() { printf "${CYAN}[INFO]${NC} %s\n" "$*"; }
ok()   { printf "${GREEN}[ OK ]${NC} %s\n" "$*"; }
warn() { printf "${YELLOW}[WARN]${NC} %s\n" "$*" >&2; }
fail() { printf "${RED}[FAIL]${NC} %s\n" "$*" >&2; }
die()  { fail "$*"; exit 1; }

usage() {
    # 打印文件头部的注释块，避免行号随维护漂移。
    awk 'NR > 1 && /^#/ { sub(/^# ?/, ""); print; next }
         NR > 1 && !/^#/ { exit }' "${BASH_SOURCE[0]}"
    printf '\n别名：agentseccore/agent-sec-core，sight/agentsight，cosh/cosh-ng，all\n'
}

# ---------------------------------------------------------------------------
# 组件定义
# ---------------------------------------------------------------------------
# 规范化入参；未知组件返回 1。
normalize_component() {
    case "${1,,}" in
        agentseccore|agent-sec-core|sec-core|agentseccore) echo "agentseccore" ;;
        sight|agentsight)                                  echo "sight" ;;
        cosh|cosh-ng)                                      echo "cosh" ;;
        *) return 1 ;;
    esac
}

# 组件对应的 RPM 包名（按卸载优先级）。
packages_of() {
    case "$1" in
        agentseccore) printf '%s\n' agent-sec-core agent-sec-plugins agent-sec-skills ;;
        sight)        printf '%s\n' agentsight agentsight-core agentsight-plugins ;;
        cosh)         printf '%s\n' cosh-ng ;;
    esac
}

# 组件对应的常驻单元（cosh 的模板实例单独处理）。
units_of() {
    case "$1" in
        agentseccore) printf '%s\n' agent-sec-core.service ;;
        sight)        printf '%s\n' agentsight.service agentsight-enforcer.service ;;
        cosh)         printf '%s\n' "cosh-gateway@${COSH_INSTANCE}.service" ;;
    esac
}

# 该组件在 scripts/rpm-build.sh 里的目标名。
build_target_of() {
    case "$1" in
        agentseccore) echo agent-sec-core ;;
        sight)        echo agentsight ;;
        cosh)         echo cosh-ng ;;
    esac
}

# ---------------------------------------------------------------------------
# 通用工具
# ---------------------------------------------------------------------------
# 在 $RPMS_X86 / $RPMS_NOARCH 中按 glob 取版本最高的 RPM，输出绝对路径。
latest_rpm() {
    local pattern="$1" candidate version file best_version="" best_file=""
    local -a files=()

    shopt -s nullglob
    # shellcheck disable=SC2206  # 需要按 glob 展开
    files=( $pattern )
    shopt -u nullglob
    ((${#files[@]})) || return 1

    for candidate in "${files[@]}"; do
        version="$(rpm -qp --qf '%{VERSION}-%{RELEASE}' "$candidate" 2>/dev/null)" || continue
        [[ -n $version ]] || continue
        if [[ -z $best_version ]] || [[ $(printf '%s\n%s\n' "$best_version" "$version" | sort -V | tail -1) == "$version" ]]; then
            best_version=$version
            best_file=$candidate
        fi
    done
    [[ -n $best_file ]] || return 1
    printf '%s\n' "$best_file"
}

# 等待 unit 进入 active，超时返回失败。
wait_unit_active() {
    local unit="$1" deadline=$((SECONDS + ${2:-$WAIT_SECONDS}))
    while ((SECONDS < deadline)); do
        [[ $(systemctl is-active "$unit" 2>/dev/null || true) == active ]] && return 0
        sleep 1
    done
    return 1
}

# 崩溃重启循环里的 attempt 也会被 is-active 报成 active（实测秒退进程仍能命中），
# 因此进入 active 后再复核 2 秒：仍在 active 且 MainPID 未变，才算真的起来了。
confirm_unit_stable() {
    local unit="$1" pid
    pid="$(systemctl show -p MainPID --value "$unit" 2>/dev/null)"
    sleep 2
    [[ $(systemctl is-active "$unit" 2>/dev/null || true) == active ]] || return 1
    [[ -n $pid && $(systemctl show -p MainPID --value "$unit" 2>/dev/null) == "$pid" ]]
}

# HTTP 探活：只要有合法状态码（含 401/403）就算服务在响应。
http_probe() {
    local url="$1" code
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$url" 2>/dev/null || true)"
    [[ $code =~ ^[0-9]{3}$ && $code != 000 ]]
}

# 等待 unix socket 出现（服务刚 active 时 socket 可能晚一拍）。
wait_socket() {
    local path="$1" deadline=$((SECONDS + ${2:-$WAIT_SECONDS}))
    while ((SECONDS < deadline)); do
        [[ -S $path ]] && return 0
        sleep 1
    done
    return 1
}

# 等待 HTTP 响应，避免服务刚 listening 时的连接拒绝被当成失败。
wait_http() {
    local url="$1" deadline=$((SECONDS + ${2:-$WAIT_SECONDS}))
    while ((SECONDS < deadline)); do
        http_probe "$url" && return 0
        sleep 1
    done
    return 1
}

# 停止并 disable 组件单元，忽略“单元不存在/未加载”。
stop_component() {
    local comp="$1" unit
    while IFS= read -r unit; do
        [[ -n $unit ]] || continue
        systemctl stop "$unit" 2>/dev/null || true
        systemctl disable "$unit" 2>/dev/null || true
        info "已停止并 disable：$unit"
    done < <(units_of "$comp")

    if [[ $comp == cosh ]]; then
        # 模板单元的所有实例都要停，避免 preun 拒绝卸载。
        systemctl list-units --all --plain --no-legend 'cosh-gateway@*.service' 2>/dev/null |
            awk '{print $1}' | while IFS= read -r unit; do
                [[ -n $unit ]] || continue
                systemctl stop "$unit" 2>/dev/null || true
                systemctl disable "$unit" 2>/dev/null || true
                info "已停止并 disable：$unit"
            done
    fi
}

# 卸载组件 RPM；未安装的包自动跳过，卸载后逐个复核。
uninstall_component() {
    local comp="$1" pkg
    local -a installed=()

    while IFS= read -r pkg; do
        if rpm -q "$pkg" >/dev/null 2>&1; then installed+=("$pkg"); fi
    done < <(packages_of "$comp")

    if ((${#installed[@]} == 0)); then
        info "组件 $comp 的 RPM 均未安装，跳过卸载"
    else
        info "卸载：${installed[*]}"
        dnf remove -y "${installed[@]}"
    fi

    systemctl daemon-reload 2>/dev/null || true

    while IFS= read -r pkg; do
        if rpm -q "$pkg" >/dev/null 2>&1; then
            fail "卸载后仍存在：$pkg"
            return 1
        fi
    done < <(packages_of "$comp")
    return 0
}

# 调用统一构建脚本；构建前打时间戳，构建后校验产物确实是新生成的。
build_component() {
    local comp="$1" target marker log rpm
    target="$(build_target_of "$comp")"
    marker="$LOG_DIR/${comp}.build-start"
    log="$LOG_DIR/${comp}-build.log"
    : > "$marker"

    info "构建 $target（日志：$log）"
    case "$comp" in
        sight)
            # 历史问题：openssl-sys 内置编译 OpenSSL 时 perl Configure 失败。
            if ! OPENSSL_NO_VENDOR=1 "$RPM_BUILD" "$target" >"$log" 2>&1; then
                tail -n 25 "$log" >&2 || true
                fail "构建失败：$target"
                return 1
            fi
            ;;
        cosh)
            # FatLTO 并行度过高会触发 rustc 中间对象缺失/ICE，固定较低并发。
            if ! CARGO_BUILD_JOBS="${CARGO_BUILD_JOBS:-4}" "$RPM_BUILD" "$target" >"$log" 2>&1; then
                tail -n 25 "$log" >&2 || true
                fail "构建失败：$target"
                return 1
            fi
            ;;
        *)
            if ! "$RPM_BUILD" "$target" >"$log" 2>&1; then
                tail -n 25 "$log" >&2 || true
                fail "构建失败：$target"
                return 1
            fi
            ;;
    esac

    if ! grep -q '\[OK\]' "$log"; then
        tail -n 25 "$log" >&2 || true
        fail "构建日志中没有成功标记：$log"
        return 1
    fi

    # 只认本次构建产生的包：必须 -nt marker，并用清单锁定给 install 使用。
    local -a built=() fresh=()
    local expected
    mapfile -t built < <(component_rpms "$comp" || true)
    for rpm in "${built[@]}"; do
        if [[ $rpm -nt $marker ]]; then fresh+=("$rpm"); fi
    done
    case "$comp" in
        agentseccore|sight) expected=3 ;;
        cosh)               expected=1 ;;
    esac
    if ((${#fresh[@]} != expected)); then
        fail "本次构建产物数量不符：期望 $expected 个，实际 ${#fresh[@]} 个"
        return 1
    fi
    printf '%s\n' "${fresh[@]}" > "$LOG_DIR/${comp}.rpms"

    # 记录本次构建的 SRPM，清理时同样保留一份。
    local src_glob
    local -a srcs=() src_fresh=()
    src_glob="$(component_srpm_glob "$comp")"
    shopt -s nullglob
    # shellcheck disable=SC2206  # 需要按 glob 展开
    srcs=( $src_glob )
    shopt -u nullglob
    for src in "${srcs[@]}"; do
        if [[ $src -nt $marker ]]; then src_fresh+=("$src"); fi
    done
    printf '%s\n' "${src_fresh[@]}" > "$LOG_DIR/${comp}.srpms"

    # RPMS 目录可能残留更高版本的历史包，提醒但不改变“装本次构建产物”的语义。
    local main_fresh="${fresh[0]}" main_latest=""
    case "$comp" in
        agentseccore) main_latest="$(latest_rpm "$RPMS_X86"/agent-sec-core-*.rpm || true)" ;;
        sight)        main_latest="$(latest_rpm "$RPMS_X86"/agentsight-[0-9]*.rpm || true)" ;;
        cosh)         main_latest="$(latest_rpm "$RPMS_X86"/cosh-ng-*.rpm || true)" ;;
    esac
    if [[ -n $main_latest && $main_latest != "$main_fresh" ]]; then
        warn "RPMS 目录中存在其他版本：$(basename "$main_latest")；本次仍安装 $(basename "$main_fresh")"
    fi
    prune_component "$comp"
    ok "构建完成：$target"
}

# 列出组件应安装的 RPM（每个包取最高版本）。
component_rpms() {
    local comp="$1" path
    case "$comp" in
        agentseccore)
            for path in "$RPMS_X86"/agent-sec-core-*.rpm \
                        "$RPMS_X86"/agent-sec-plugins-*.rpm \
                        "$RPMS_X86"/agent-sec-skills-*.rpm; do
                latest_rpm "$path" || return 1
            done
            ;;
        sight)
            for path in "$RPMS_X86"/agentsight-core-*.rpm \
                        "$RPMS_X86"/agentsight-[0-9]*.rpm \
                        "$RPMS_NOARCH"/agentsight-plugins-*.rpm; do
                latest_rpm "$path" || return 1
            done
            ;;
        cosh)
            latest_rpm "$RPMS_X86"/cosh-ng-*.rpm || return 1
            ;;
    esac
}

# 组件主包的 SRPM glob（构建记录与清理共用）。
component_srpm_glob() {
    case "$1" in
        agentseccore) printf '%s\n' "$RPM_TOP/SRPMS/agent-sec-core-*.src.rpm" ;;
        sight)        printf '%s\n' "$RPM_TOP/SRPMS/agentsight-*.src.rpm" ;;
        cosh)         printf '%s\n' "$RPM_TOP/SRPMS/cosh-ng-*.src.rpm" ;;
    esac
}

# 清理同组件的历史版本，只保留本次构建产物（每个包一份）。
prune_component() {
    local comp="$1" pattern rpm removed=0
    local -a keep=() keep_src=() patterns=()

    [[ ${KEEP_ARTIFACTS:-0} == 1 ]] && { info "KEEP_ARTIFACTS=1，保留历史产物"; return 0; }
    [[ -s "$LOG_DIR/${comp}.rpms" ]] || return 0
    mapfile -t keep < "$LOG_DIR/${comp}.rpms"
    if [[ -s "$LOG_DIR/${comp}.srpms" ]]; then
        mapfile -t keep_src < "$LOG_DIR/${comp}.srpms"
    fi

    case "$comp" in
        agentseccore)
            patterns=("$RPMS_X86"/agent-sec-core-*.rpm "$RPMS_X86"/agent-sec-plugins-*.rpm
                      "$RPMS_X86"/agent-sec-skills-*.rpm)
            ;;
        sight)
            patterns=("$RPMS_X86"/agentsight-core-*.rpm "$RPMS_X86"/agentsight-[0-9]*.rpm
                      "$RPMS_NOARCH"/agentsight-plugins-*.rpm)
            ;;
        cosh)
            patterns=("$RPMS_X86"/cosh-ng-*.rpm)
            ;;
    esac
    patterns+=("$(component_srpm_glob "$comp")")

    shopt -s nullglob
    for pattern in "${patterns[@]}"; do
        for rpm in $pattern; do
            if [[ $rpm == *.src.rpm ]]; then
                [[ " ${keep_src[*]-} " == *" $rpm "* ]] && continue
            else
                [[ " ${keep[*]} " == *" $rpm "* ]] && continue
            fi
            rm -f -- "$rpm"
            removed=$((removed + 1))
            info "清理历史产物：$(basename "$rpm")"
        done
    done
    shopt -u nullglob

    if ((removed > 0)); then
        ok "已清理 $removed 个历史产物，每个包只保留本次构建版本"
    fi
}

# 安装组件 RPM（dnf 会自动解析子包依赖顺序）。
install_component() {
    local comp="$1"
    local -a rpms=()
    local manifest="$LOG_DIR/${comp}.rpms" rpm

    if [[ ! -s $manifest ]]; then
        fail "缺少本次构建产物清单：$manifest"
        return 1
    fi
    mapfile -t rpms < "$manifest"
    for rpm in "${rpms[@]}"; do
        if [[ ! -f $rpm ]]; then
            fail "产物文件不存在：$rpm"
            return 1
        fi
    done

    info "安装：$(printf '%s ' "${rpms[@]##*/}")"
    dnf install -y "${rpms[@]}"

    for rpm in "${rpms[@]}"; do
        rpm -qp --qf '已安装：%{NAME}-%{VERSION}-%{RELEASE}.%{ARCH}\n' "$rpm"
    done

    # 确认系统上没有同名包的多版本共存。
    local pkg dup
    while IFS= read -r pkg; do
        [[ -n $pkg ]] || continue
        dup="$(rpm -q --qf '%{VERSION}-%{RELEASE}\n' "$pkg" 2>/dev/null | sort -u | wc -l)"
        if ((dup > 1)); then
            warn "系统上存在多个版本：$(rpm -q "$pkg" | tr '\n' ' ')"
        fi
    done < <(packages_of "$comp")
    ok "安装完成：$comp"
}

# cosh 网关模板单元要求 EnvironmentFile 必须先存在。
ensure_cosh_env() {
    local env_file="/etc/cosh/gateway-${COSH_INSTANCE}.env"
    if [[ ! -f $env_file ]]; then
        mkdir -p /etc/cosh
        printf 'COSH_GATEWAY_WORKSPACE=%s\n' "$COSH_WORKSPACE" > "$env_file"
        chmod 0600 "$env_file"
        info "已创建 $env_file"
    fi
}

# enable --now 组件服务（不在这里判断健康，健康检查在 check_component）。
start_component() {
    local comp="$1"
    case "$comp" in
        agentseccore)
            systemctl enable --now agent-sec-core.service
            ;;
        sight)
            systemctl enable --now agentsight.service agentsight-enforcer.service
            ;;
        cosh)
            ensure_cosh_env
            systemctl enable --now "cosh-gateway@${COSH_INSTANCE}.service"
            ;;
    esac
}

# 服务启动检查：unit active + 组件特有探针（socket / HTTP）。
check_component() {
    local comp="$1" unit rc=0
    while IFS= read -r unit; do
        [[ -n $unit ]] || continue
        if wait_unit_active "$unit" "$WAIT_SECONDS" && confirm_unit_stable "$unit"; then
            ok "服务运行中：$unit（$(systemctl show -p MainPID --value "$unit" 2>/dev/null)）"
        else
            fail "服务未稳定运行：$unit（$(systemctl is-active "$unit" 2>/dev/null || true)，NRestarts=$(systemctl show -p NRestarts --value "$unit" 2>/dev/null)）"
            rc=1
        fi
    done < <(units_of "$comp")

    case "$comp" in
        agentseccore)
            # 单元 active 即视为通过；daemon 没有对外监听端口。
            ;;
        sight)
            if wait_socket /run/agentsight/enforcer.sock; then
                ok "enforcer socket 就绪：/run/agentsight/enforcer.sock"
            else
                fail "enforcer socket 缺失：/run/agentsight/enforcer.sock"
                rc=1
            fi
            if wait_http "http://127.0.0.1:${AGENTSIGHT_PORT}/"; then
                ok "AgentSight server 有响应：http://127.0.0.1:${AGENTSIGHT_PORT}/"
            else
                fail "AgentSight server 无响应：http://127.0.0.1:${AGENTSIGHT_PORT}/"
                rc=1
            fi
            ;;
        cosh)
            if wait_socket "/run/cosh-gateway-${COSH_INSTANCE}/gateway.sock"; then
                ok "gateway socket 就绪：/run/cosh-gateway-${COSH_INSTANCE}/gateway.sock"
            else
                fail "gateway socket 缺失：/run/cosh-gateway-${COSH_INSTANCE}/gateway.sock"
                rc=1
            fi
            ;;
    esac
    return "$rc"
}

# 构建前置工具检查，缺工具时给出安装命令。
preflight() {
    local -a missing=()
    local cmd
    for cmd in rpmbuild cargo rustc dnf systemctl curl flock; do
        command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
    done
    if printf '%s\n' "$@" | grep -qx sight; then
        for cmd in node npm clang; do
            command -v "$cmd" >/dev/null 2>&1 || missing+=("$cmd")
        done
    fi
    if ((${#missing[@]})); then
        fail "缺少构建工具：${missing[*]}"
        printf '可执行：dnf install -y rpm-build cargo rust nodejs npm clang clang-devel \\\n' >&2
        printf '        llvm-devel systemd-rpm-macros glibc-static perl-core \\\n' >&2
        printf '        elfutils-libelf-devel zlib-devel libbpf-devel cmake openssl-devel\n' >&2
        return 1
    fi
    [[ -f $RPM_BUILD && -x $RPM_BUILD ]] || { fail "构建脚本不可执行：$RPM_BUILD"; return 1; }
    mkdir -p "$LOG_DIR"
    ok "前置检查通过（日志目录：$LOG_DIR）"
}

# ---------------------------------------------------------------------------
# 主流程
# ---------------------------------------------------------------------------
main() {
    local -a components=()
    local arg comp

    if (($# == 0)); then usage; exit 1; fi
    for arg in "$@"; do
        case "$arg" in
            -h|--help) usage; exit 0 ;;
            all) components+=(agentseccore sight cosh) ;;
            *)
                if ! comp="$(normalize_component "$arg")"; then
                    fail "未知组件：$arg"
                    usage
                    exit 1
                fi
                components+=("$comp")
                ;;
        esac
    done

    # 去重并保持入参顺序。
    local -a selected=()
    for comp in "${components[@]}"; do
        [[ " ${selected[*]-} " == *" $comp "* ]] && continue
        selected+=("$comp")
    done
    components=("${selected[@]}")

    [[ $EUID -eq 0 ]] || die "需要 root 权限（卸载/安装 RPM、启停 systemd 服务）"
    preflight "${components[@]}"

    # 统一加锁：rpmbuild 的 _topdir 是共享的，并发构建会互相清理 target 目录。
    exec 9>"$BUILD_LOCK"
    if ! flock -w 1800 9; then
        die "等待构建锁超时：$BUILD_LOCK（可能已有构建在运行）"
    fi

    info "本次组件：${components[*]}"
    info "仓库根：$ROOT"

    declare -A STATUS_BUILD=() STATUS_INSTALL=() STATUS_SVC=()
    local rc_total=0 step_ok

    for comp in "${components[@]}"; do
        printf '\n========== %s ==========\n' "$comp"
        STATUS_BUILD[$comp]="-"
        STATUS_INSTALL[$comp]="-"
        STATUS_SVC[$comp]="-"

        info "1/4 停止并卸载"
        if ! stop_component "$comp" || ! uninstall_component "$comp"; then
            fail "$comp：卸载失败，跳过后续步骤"
            STATUS_BUILD[$comp]="skipped"
            STATUS_INSTALL[$comp]="skipped"
            STATUS_SVC[$comp]="skipped"
            rc_total=1
            continue
        fi

        info "2/4 编译 RPM"
        if build_component "$comp"; then
            STATUS_BUILD[$comp]="ok"
        else
            STATUS_BUILD[$comp]="FAIL"
            STATUS_INSTALL[$comp]="skipped"
            STATUS_SVC[$comp]="skipped"
            rc_total=1
            continue
        fi

        info "3/4 安装 RPM"
        if install_component "$comp"; then
            STATUS_INSTALL[$comp]="ok"
        else
            STATUS_INSTALL[$comp]="FAIL"
            STATUS_SVC[$comp]="skipped"
            rc_total=1
            continue
        fi

        info "4/4 启动并检查服务"
        step_ok=1
        start_component "$comp" || step_ok=0
        if ((step_ok == 1)) && check_component "$comp"; then
            STATUS_SVC[$comp]="ok"
        else
            STATUS_SVC[$comp]="FAIL"
            rc_total=1
        fi
    done

    printf '\n================ 汇总 ================\n'
    printf '%-14s %-8s %-8s %s\n' "组件" "构建" "安装" "服务"
    for comp in "${components[@]}"; do
        printf '%-14s %-8s %-8s %s\n' \
            "$comp" "${STATUS_BUILD[$comp]}" "${STATUS_INSTALL[$comp]}" "${STATUS_SVC[$comp]}"
    done
    printf '\n日志目录：%s\n' "$LOG_DIR"
    if ((rc_total == 0)); then
        ok "全部组件完成"
    else
        fail "存在失败步骤，请查看上方日志与 $LOG_DIR"
    fi
    return "$rc_total"
}

main "$@"
