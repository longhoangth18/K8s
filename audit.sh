#!/usr/bin/env bash
set -euo pipefail

# ========= CONFIG =========
AUDIT_DIR="/etc/kubernetes/audit"
POLICY_FILE="${AUDIT_DIR}/audit-policy.yaml"

AUDIT_LOG_DIR="/var/log/kubernetes/audit"
AUDIT_LOG_FILE="${AUDIT_LOG_DIR}/audit.log"

APISERVER_MANIFEST="/etc/kubernetes/manifests/kube-apiserver.yaml"

# kube-apiserver audit rotation flags (theo docs)
MAXAGE="30"
MAXBACKUP="10"
MAXSIZE="100"  # MB

# timeout chờ apiserver ready sau khi restart
WAIT_SEC="180"
SLEEP_STEP="3"

# ========= PRECHECK =========
if [[ $EUID -ne 0 ]]; then
  echo "ERROR: run as root (sudo)." >&2
  exit 1
fi

if [[ ! -f "${APISERVER_MANIFEST}" ]]; then
  echo "ERROR: ${APISERVER_MANIFEST} not found. Script này giả định kubeadm static pod." >&2
  exit 1
fi

# deps: python3 + PyYAML để sửa YAML đúng cấu trúc
if ! command -v python3 >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y python3
fi
if ! python3 -c 'import yaml' >/dev/null 2>&1; then
  apt-get update -y
  apt-get install -y python3-yaml
fi

# ========= SETUP FILES =========
echo "[1/9] Create audit directories"
mkdir -p "${AUDIT_DIR}" "${AUDIT_LOG_DIR}"
chmod 700 "${AUDIT_DIR}" "${AUDIT_LOG_DIR}"

echo "[2/9] Create audit policy ${POLICY_FILE}"
# Policy production-friendly hơn: bỏ RequestReceived để giảm noise, log write ở RequestResponse,
# read chỉ Metadata; bỏ healthz/readyz/metrics [web:1]
cat > "${POLICY_FILE}" <<'YAML'
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

  # Reads: keep metadata
  - level: Metadata
    verbs: ["get","list","watch"]

  # Writes: keep request+response
  - level: RequestResponse
    verbs: ["create","update","patch","delete","deletecollection"]
YAML
chmod 600 "${POLICY_FILE}"

echo "[3/9] Ensure audit log file exists ${AUDIT_LOG_FILE}"
touch "${AUDIT_LOG_FILE}"
chmod 600 "${AUDIT_LOG_FILE}"

echo "[4/9] Backup kube-apiserver manifest"
BACKUP="${APISERVER_MANIFEST}.bak.$(date +%Y%m%d%H%M%S)"
cp -a "${APISERVER_MANIFEST}" "${BACKUP}"
echo "Backup saved: ${BACKUP}"

# ========= PATCH kube-apiserver static pod =========
echo "[5/9] Patch ${APISERVER_MANIFEST} (flags + volumeMounts + volumes)"
python3 - <<PY
import yaml

m_path="${APISERVER_MANIFEST}"
policy="${POLICY_FILE}"
log_dir="${AUDIT_LOG_DIR}"
log_file="${AUDIT_LOG_FILE}"
maxage="${MAXAGE}"
maxbackup="${MAXBACKUP}"
maxsize="${MAXSIZE}"

doc=yaml.safe_load(open(m_path))
c=doc["spec"]["containers"][0]
cmd=c.get("command", [])

def setflag(prefix, val):
    out=[x for x in cmd if not x.startswith(prefix)]
    out.append(f"{prefix}{val}")
    return out

# Bật audit backend đúng chuẩn flags [web:1]
cmd=setflag("--audit-policy-file=", policy)
cmd=setflag("--audit-log-path=", log_file)
cmd=setflag("--audit-log-maxage=", maxage)
cmd=setflag("--audit-log-maxbackup=", maxbackup)
cmd=setflag("--audit-log-maxsize=", maxsize)
c["command"]=cmd

vms=c.get("volumeMounts", [])
def ensure_vm(name, mountPath, readOnly):
    for vm in vms:
        if vm.get("name")==name:
            vm["mountPath"]=mountPath
            vm["readOnly"]=bool(readOnly)
            return
    vms.append({"name":name, "mountPath":mountPath, "readOnly":bool(readOnly)})

# Nếu apiserver chạy dạng Pod, cần hostPath mount policy/log để persist [web:1]
ensure_vm("audit-policy", policy, True)
ensure_vm("audit-logs", log_dir, False)
c["volumeMounts"]=vms

vols=doc["spec"].get("volumes", [])
def ensure_vol(name, hostPath, type_):
    for v in vols:
        if v.get("name")==name:
            v["hostPath"]={"path":hostPath, "type":type_}
            return
    vols.append({"name":name, "hostPath":{"path":hostPath, "type":type_}})

ensure_vol("audit-policy", policy, "File")
ensure_vol("audit-logs", log_dir, "DirectoryOrCreate")
doc["spec"]["volumes"]=vols

yaml.safe_dump(doc, open(m_path, "w"), default_flow_style=False, sort_keys=False)
PY

# ========= WAIT apiserver =========
echo "[6/9] Wait for apiserver ready (kubelet will restart static pod)"
deadline=$((SECONDS+WAIT_SEC))
while [[ $SECONDS -lt $deadline ]]; do
  if curl -sk https://127.0.0.1:6443/readyz >/dev/null 2>&1; then
    echo "apiserver ready"
    break
  fi
  sleep "${SLEEP_STEP}"
done

if ! curl -sk https://127.0.0.1:6443/readyz >/dev/null 2>&1; then
  echo "ERROR: apiserver not ready within ${WAIT_SEC}s." >&2
  echo "Rollback to backup: ${BACKUP}" >&2
  cp -a "${BACKUP}" "${APISERVER_MANIFEST}"
  sleep 15
  exit 2
fi

# ========= VERIFY =========
echo "[7/9] Verify audit flags in manifest"
grep -nE -- '--audit-policy-file=|--audit-log-path=|--audit-log-maxage=|--audit-log-maxbackup=|--audit-log-maxsize=' \
  "${APISERVER_MANIFEST}" || true

echo "[8/9] Smoke test: generate audit events"
if command -v kubectl >/dev/null 2>&1; then
  NS="audit-log-test-$(date +%s)"
  kubectl create ns "${NS}" >/dev/null
  kubectl delete ns "${NS}" --wait=false >/dev/null
  sleep 2
  echo "Audit log lines for ${NS}:"
  tail -n 800 "${AUDIT_LOG_FILE}" | grep -E "\"name\":\"${NS}\"|\"namespace\":\"${NS}\"|${NS}" | tail -n 50 || true
else
  echo "kubectl not found, skipping kubectl smoke test."
  echo "Manual test:"
  echo "  NS=audit-log-test-\$(date +%s); kubectl create ns \$NS; kubectl delete ns \$NS --wait=false"
  echo "  sudo tail -n 800 ${AUDIT_LOG_FILE} | grep \$NS"
fi

echo "[9/9] Done. Audit log path: ${AUDIT_LOG_FILE}"
