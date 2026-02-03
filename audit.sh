#!/usr/bin/env bash
set -euo pipefail

AUTO_ROLLBACK="${AUTO_ROLLBACK:-0}"   # 1 = rollback nếu verify fail

AUDIT_DIR="/etc/kubernetes/audit"
POLICY_FILE="${AUDIT_DIR}/audit-policy.yaml"
AUDIT_LOG_DIR="/var/log/kubernetes/audit"
AUDIT_LOG_FILE="${AUDIT_LOG_DIR}/audit.log"
APISERVER_MANIFEST="/etc/kubernetes/manifests/kube-apiserver.yaml"

MAXAGE="30"; MAXBACKUP="10"; MAXSIZE="100"
WAIT_SEC="240"; SLEEP_STEP="3"; READY_STREAK_REQUIRED="3"
TEST_WAIT_AFTER_EVENTS="6"
GREP_LINES="5000"

die(){ echo "ERROR: $*" >&2; exit 1; }
readyz_ok(){ curl -sk --max-time 2 https://127.0.0.1:6443/readyz >/dev/null 2>&1; }

get_apiserver_cid() {
  crictl ps -a --name kube-apiserver -q 2>/dev/null | head -n1 || true
}

debug_dump() {
  echo "===== DEBUG: apiserver flags in manifest ====="
  grep -nE -- '--audit-policy-file=|--audit-log-path=|--audit-log-maxage=|--audit-log-maxbackup=|--audit-log-maxsize=' \
    "$APISERVER_MANIFEST" || true

  echo "===== DEBUG: file permissions ====="
  ls -ld "$AUDIT_DIR" "$AUDIT_LOG_DIR" || true
  ls -l "$POLICY_FILE" "$AUDIT_LOG_FILE" || true

  echo "===== DEBUG: last apiserver logs ====="
  cid="$(get_apiserver_cid)"
  echo "CID=$cid"
  if [[ -n "${cid:-}" ]]; then
    crictl logs "$cid" 2>/dev/null | tail -n 200 || true
  fi

  echo "===== DEBUG: audit.log tail ====="
  tail -n 50 "$AUDIT_LOG_FILE" || true
}

rollback() {
  local backup="$1"
  echo "Rollback -> $backup"
  cp -a "$backup" "$APISERVER_MANIFEST"
  sleep 15
}

[[ $EUID -eq 0 ]] || die "Run as root (sudo)."
[[ -f "$APISERVER_MANIFEST" ]] || die "Missing $APISERVER_MANIFEST (kubeadm static pod expected)."
command -v kubectl >/dev/null 2>&1 || die "kubectl not found."

if ! command -v python3 >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y python3
fi
if ! python3 -c 'import yaml' >/dev/null 2>&1; then
  apt-get update -y && apt-get install -y python3-yaml
fi

echo "[1/10] Create directories"
mkdir -p "$AUDIT_DIR" "$AUDIT_LOG_DIR"
chmod 700 "$AUDIT_DIR" "$AUDIT_LOG_DIR"

echo "[2/10] Write audit policy"
cat > "$POLICY_FILE" <<'YAML'
apiVersion: audit.k8s.io/v1
kind: Policy
omitStages:
  - "RequestReceived"
rules:
  - level: None
    nonResourceURLs:
      - /healthz*
      - /readyz*
      - /livez*
      - /metrics
      - /version
      - /swagger*
      - /openapi*
  - level: Metadata
    verbs: ["get","list","watch"]
  - level: RequestResponse
    verbs: ["create","update","patch","delete","deletecollection"]
YAML
chmod 600 "$POLICY_FILE"

echo "[3/10] Prepare audit log path"
touch "$AUDIT_LOG_FILE"
chmod 600 "$AUDIT_LOG_FILE"

echo "[4/10] Backup kube-apiserver manifest"
BACKUP="${APISERVER_MANIFEST}.bak.$(date +%Y%m%d%H%M%S)"
cp -a "$APISERVER_MANIFEST" "$BACKUP"
echo "Backup: $BACKUP"

echo "[5/10] Patch apiserver manifest"
python3 - <<PY
import yaml
m_path="${APISERVER_MANIFEST}"
policy="${POLICY_FILE}"
log_dir="${AUDIT_LOG_DIR}"
log_file="${AUDIT_LOG_FILE}"
maxage="${MAXAGE}"; maxbackup="${MAXBACKUP}"; maxsize="${MAXSIZE}"

doc=yaml.safe_load(open(m_path))
c=doc["spec"]["containers"][0]
cmd=c.get("command",[])

def setflag(prefix,val):
    out=[x for x in cmd if not x.startswith(prefix)]
    out.append(f"{prefix}{val}")
    return out

cmd=setflag("--audit-policy-file=", policy)
cmd=setflag("--audit-log-path=", log_file)
cmd=setflag("--audit-log-maxage=", maxage)
cmd=setflag("--audit-log-maxbackup=", maxbackup)
cmd=setflag("--audit-log-maxsize=", maxsize)
c["command"]=cmd

vms=c.get("volumeMounts",[])
def ensure_vm(name,path,ro):
    for vm in vms:
        if vm.get("name")==name:
            vm["mountPath"]=path; vm["readOnly"]=bool(ro); return
    vms.append({"name":name,"mountPath":path,"readOnly":bool(ro)})

ensure_vm("audit-policy", policy, True)
ensure_vm("audit-logs", log_dir, False)
c["volumeMounts"]=vms

vols=doc["spec"].get("volumes",[])
def ensure_vol(name,path,type_):
    for v in vols:
        if v.get("name")==name:
            v["hostPath"]={"path":path,"type":type_}; return
    vols.append({"name":name,"hostPath":{"path":path,"type":type_}})

ensure_vol("audit-policy", policy, "File")
ensure_vol("audit-logs", log_dir, "DirectoryOrCreate")
doc["spec"]["volumes"]=vols

yaml.safe_dump(doc, open(m_path,"w"), default_flow_style=False, sort_keys=False)
PY

echo "[6/10] Wait apiserver ready (stable)"
deadline=$((SECONDS+WAIT_SEC))
streak=0
while [[ $SECONDS -lt $deadline ]]; do
  if readyz_ok; then
    streak=$((streak+1))
    echo "readyz ok (${streak}/${READY_STREAK_REQUIRED})"
    [[ $streak -ge $READY_STREAK_REQUIRED ]] && break
  else
    streak=0
  fi
  sleep "$SLEEP_STEP"
done
[[ $streak -ge $READY_STREAK_REQUIRED ]] || { debug_dump; [[ "$AUTO_ROLLBACK" == "1" ]] && rollback "$BACKUP"; die "apiserver not stable ready"; }

echo "[7/10] Generate events"
NS="audit-log-test-$(date +%s)"
kubectl create ns "$NS" >/dev/null
kubectl delete ns "$NS" --wait=false >/dev/null

echo "[8/10] Wait ${TEST_WAIT_AFTER_EVENTS}s for audit flush"
sleep "$TEST_WAIT_AFTER_EVENTS"

echo "[9/10] Verify audit log contains namespace token"
if ! tail -n "$GREP_LINES" "$AUDIT_LOG_FILE" | grep -q "$NS"; then
  echo "VERIFY FAIL: audit.log doesn't contain $NS"
  debug_dump
  [[ "$AUTO_ROLLBACK" == "1" ]] && rollback "$BACKUP"
  exit 2
fi

echo "[10/10] OK: audit logging enabled and verified."
echo "Audit log: $AUDIT_LOG_FILE"
tail -n "$GREP_LINES" "$AUDIT_LOG_FILE" | grep "$NS" | tail -n 5 || true
