FROM alibaba-cloud-linux-4-registry.cn-hangzhou.cr.aliyuncs.com/alinux4/alinux4@sha256:5df52514a0231cedc12cc699d99470e8f170ad16dd3d8c7840aa9bab205c91a0
SHELL ["/bin/bash", "-euo", "pipefail", "-c"]
COPY packages/ /tmp/demo-packages/
COPY versions.json /opt/demo/versions.json
RUN sed -i 's/mirrors.cloud.aliyuncs.com/mirrors.aliyun.com/g' /etc/yum.repos.d/*.repo \
    && python3 -c 'import hashlib,json,pathlib; d=json.load(open("/opt/demo/versions.json")); p=pathlib.Path("/tmp/demo-packages"); assert all(hashlib.sha256((p/n).read_bytes()).hexdigest()==h for n,h in d["packages"].items())' \
    && dnf install -y --setopt=install_weak_deps=False /tmp/demo-packages/*.rpm nodejs npm procps-ng curl libcap git \
    && python3 -c 'import base64,hashlib,json;d=json.load(open("/opt/demo/versions.json")); b=open("/tmp/demo-packages/qodercli-1.1.48.tgz","rb").read(); assert "sha512-"+base64.b64encode(hashlib.sha512(b).digest()).decode()==d["qoder_npm_integrity"]' \
    && npm install --global --prefix /usr/local --no-audit --no-fund /tmp/demo-packages/qodercli-1.1.48.tgz \
    && test "$(node -p 'require("/usr/local/lib/node_modules/@qoder-ai/qodercli/package.json").version')" = 1.1.48 \
    && (setcap -r "$(command -v agentsight)" || test -z "$(getcap "$(command -v agentsight)")") \
    && useradd --create-home --uid 1000 --shell /bin/bash demo \
    && mkdir -p /var/log/sysak \
    && ln -s /home/demo/.local/share/agentsight /var/log/sysak/.agentsight \
    && rpm -qa | sort > /opt/demo/installed-rpms.txt \
    && dnf clean all && rm -rf /tmp/demo-packages /root/.npm /root/.qoder
COPY runtime.sh /opt/demo/runtime.sh
RUN dnf install -y --setopt=install_weak_deps=False nodejs-full-i18n-22.23.0-1.alnx4 \
    && node -e 'if (process.version !== "v22.23.0" || [...new Intl.Segmenter("zh", {granularity:"grapheme"}).segment("体验")].length !== 2) process.exit(1)' \
    && rpm -qa | sort > /opt/demo/installed-rpms.txt \
    && dnf clean all && chmod 755 /opt/demo/runtime.sh
ENV HOME=/home/demo LANG=C.UTF-8 TERM=xterm-256color \
    XDG_RUNTIME_DIR=/home/demo/.runtime \
    AGENT_SEC_DAEMON_SOCKET=/home/demo/.runtime/agent-sec-core/daemon.sock \
    SKILL_LEDGER_HOOK_ENABLED=true SKILL_LEDGER_MODE=ask OBSERVABILITY_HOOK_ENABLED=true \
    PII_CHECKER_HOOK_ENABLED=false PROMPT_SCANNER_HOOK_ENABLED=false CODE_SCANNER_HOOK_ENABLED=false
USER 1000:1000
WORKDIR /home/demo
EXPOSE 7396
HEALTHCHECK --interval=10s --timeout=5s --start-period=90s --retries=3 CMD /opt/demo/runtime.sh health
ENTRYPOINT ["/opt/demo/runtime.sh", "serve"]
