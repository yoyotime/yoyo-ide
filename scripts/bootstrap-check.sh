#!/usr/bin/env bash
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT_DIR"

TMP_DIR="/tmp/mini-kyc-bootstrap"
mkdir -p "$TMP_DIR"

STRICT_MODE=0
REPORT_FILE=""
DIFF_FILE=""
LOCK_MODE=0
UPDATE_BASELINE=0
BASELINE_FILE="bootstrap-baseline.txt"

for arg in "$@"; do
  case "$arg" in
    --strict)
      STRICT_MODE=1
      REPORT_FILE="bootstrap-report.txt"
      DIFF_FILE="bootstrap-report-diff.txt"
      ;;
    --lock)
      LOCK_MODE=1
      ;;
    --update-baseline)
      UPDATE_BASELINE=1
      ;;
    *)
      echo "鏈煡鍙傛暟: $arg"
      echo "鐢ㄦ硶: $0 [--strict] [--lock] [--update-baseline]"
      exit 2
      ;;
  esac
done

if [[ $LOCK_MODE -eq 1 && $STRICT_MODE -ne 1 ]]; then
  echo "--lock 渚濊禆 --strict"
  echo "鐢ㄦ硶: $0 --strict [--lock] [--update-baseline]"
  exit 2
fi

if [[ $UPDATE_BASELINE -eq 1 && $STRICT_MODE -ne 1 ]]; then
  echo "--update-baseline 渚濊禆 --strict"
  echo "鐢ㄦ硶: $0 --strict [--lock] [--update-baseline]"
  exit 2
fi

echo "[1/4] 鐢熸垚 mini-kyc.ky锛堢涓€娆★級"
node create-mini-kyc3.js >/dev/null
cp projects/mini-kyc.ky "$TMP_DIR/mini-kyc-1.ky"

echo "[2/4] 鐢熸垚 mini-kyc.ky锛堢浜屾锛?
node create-mini-kyc3.js >/dev/null
cp projects/mini-kyc.ky "$TMP_DIR/mini-kyc-2.ky"

echo "[3/4] 鐢ㄥ悓涓€婧愮爜缂栬瘧涓ゆ"
node ky-compiler.js projects/mini-kyc.ky "$TMP_DIR/mini-kyc-a.exe" >/dev/null
node ky-compiler.js projects/mini-kyc.ky "$TMP_DIR/mini-kyc-b.exe" >/dev/null

echo "[4/4] 涓€鑷存€ф鏌?
cmp -s "$TMP_DIR/mini-kyc-1.ky" "$TMP_DIR/mini-kyc-2.ky"
KY_CMP_EXIT=$?

cmp -s "$TMP_DIR/mini-kyc-a.exe" "$TMP_DIR/mini-kyc-b.exe"
EXE_CMP_EXIT=$?

KY_SHA_1="$(sha256sum "$TMP_DIR/mini-kyc-1.ky" | awk '{print $1}')"
KY_SHA_2="$(sha256sum "$TMP_DIR/mini-kyc-2.ky" | awk '{print $1}')"
EXE_SHA_A="$(sha256sum "$TMP_DIR/mini-kyc-a.exe" | awk '{print $1}')"
EXE_SHA_B="$(sha256sum "$TMP_DIR/mini-kyc-b.exe" | awk '{print $1}')"

echo
echo "=== bootstrap-check 鎶ュ憡 ==="
echo "mini-kyc.ky #1 sha256: $KY_SHA_1"
echo "mini-kyc.ky #2 sha256: $KY_SHA_2"
echo "mini-kyc.ky 涓€鑷存€? $([[ $KY_CMP_EXIT -eq 0 ]] && echo PASS || echo FAIL)"
echo
echo "mini-kyc-a.exe sha256: $EXE_SHA_A"
echo "mini-kyc-b.exe sha256: $EXE_SHA_B"
echo "浜х墿涓€鑷存€? $([[ $EXE_CMP_EXIT -eq 0 ]] && echo PASS || echo FAIL)"

if [[ $STRICT_MODE -eq 1 ]]; then
  {
    echo "timestamp: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    echo "mini-kyc.ky.sha256: $KY_SHA_1"
    echo "mini-kyc.exe.sha256: $EXE_SHA_A"
    echo "mini-kyc.ky.cmp: $KY_CMP_EXIT"
    echo "mini-kyc.exe.cmp: $EXE_CMP_EXIT"
  } > "$REPORT_FILE"

  keys=(
    "mini-kyc.ky.sha256"
    "mini-kyc.exe.sha256"
    "mini-kyc.ky.cmp"
    "mini-kyc.exe.cmp"
  )

  BASELINE_CHANGED=0
  CHANGED=0
  {
    echo "=== bootstrap-report 宸紓 ==="
    echo "generated_at: $(date -u +%Y-%m-%dT%H:%M:%SZ)"
    if [[ ! -f "$BASELINE_FILE" ]]; then
      echo "baseline: missing"
      echo "status: no-baseline"
    else
      echo "baseline: $BASELINE_FILE"
      changed=0
      for key in "${keys[@]}"; do
        prev_val="$(grep -E "^${key}: " "$BASELINE_FILE" | head -n1 | sed -E "s/^${key}: //")"
        curr_val="$(grep -E "^${key}: " "$REPORT_FILE" | head -n1 | sed -E "s/^${key}: //")"
        if [[ "$prev_val" == "$curr_val" ]]; then
          echo "$key: same"
        else
          changed=1
          echo "$key: changed"
          echo "  prev: $prev_val"
          echo "  curr: $curr_val"
        fi
      done
      if [[ $changed -eq 0 ]]; then
        echo "status: identical-to-baseline"
      else
        echo "status: changed"
        CHANGED=1
        BASELINE_CHANGED=1
      fi
    fi
  } > "$DIFF_FILE"

  if [[ $UPDATE_BASELINE -eq 1 ]]; then
    {
      for key in "${keys[@]}"; do
        grep -E "^${key}: " "$REPORT_FILE"
      done
    } > "$BASELINE_FILE"
  fi

  echo
  echo "strict 鎶ュ憡宸插啓鍏? $REPORT_FILE"
  echo "strict 宸紓宸插啓鍏? $DIFF_FILE"
  if [[ $UPDATE_BASELINE -eq 1 ]]; then
    echo "strict 鍩虹嚎宸叉洿鏂? $BASELINE_FILE"
  fi

  if [[ $LOCK_MODE -eq 1 ]]; then
    if [[ ! -f "$BASELINE_FILE" ]]; then
      echo "lock 妯″紡澶辫触: 鏈壘鍒板熀绾挎枃浠?$BASELINE_FILE"
      exit 3
    fi
    if [[ $BASELINE_CHANGED -ne 0 ]]; then
      echo "lock 妯″紡澶辫触: 褰撳墠缁撴灉涓庡熀绾垮瓨鍦ㄥ樊寮?
      exit 4
    fi
    echo "lock 妯″紡: PASS锛堜笌鍩虹嚎涓€鑷达級"
  fi
fi

if [[ $KY_CMP_EXIT -ne 0 || $EXE_CMP_EXIT -ne 0 ]]; then
  echo
  echo "bootstrap-check: FAIL"
  exit 1
fi

echo
echo "bootstrap-check: PASS"
