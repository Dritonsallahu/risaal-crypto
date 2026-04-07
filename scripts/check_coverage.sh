#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# check_coverage.sh — Per-file and global coverage enforcement for risaal_crypto
#
# Usage: ./scripts/check_coverage.sh [coverage/lcov.info]
#
# Exit codes:
#   0 — All thresholds met
#   1 — One or more thresholds violated
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

LCOV_FILE="${1:-coverage/lcov.info}"

# ── Thresholds ──────────────────────────────────────────────────────────────
GLOBAL_THRESHOLD=85

# Critical crypto files require 95% coverage
declare -A CRITICAL_FILES=(
  ["lib/src/x3dh.dart"]=95
  ["lib/src/double_ratchet.dart"]=95
  ["lib/src/sender_key.dart"]=95
  ["lib/src/sealed_sender.dart"]=95
  ["lib/src/signal_protocol_manager.dart"]=90
  ["lib/src/secure_memory.dart"]=90
  ["lib/src/key_helper.dart"]=90
  ["lib/src/safety_number.dart"]=90
  ["lib/src/message_padding.dart"]=90
  ["lib/src/session_reset_errors.dart"]=85
  ["lib/src/security_event_bus.dart"]=85
  ["lib/src/stego_service.dart"]=85
)

# ── Validate input ──────────────────────────────────────────────────────────
if [ ! -f "$LCOV_FILE" ]; then
  echo "ERROR: Coverage file not found: $LCOV_FILE"
  exit 1
fi

# ── Parse lcov.info ─────────────────────────────────────────────────────────
# lcov.info format:
#   SF:<source-file>
#   DA:<line-number>,<execution-count>
#   end_of_record

GLOBAL_TOTAL=0
GLOBAL_HIT=0
FAILED=0
PASS_COUNT=0

echo "╔══════════════════════════════════════════════════════════════════╗"
echo "║           risaal_crypto — Coverage Enforcement Report          ║"
echo "╚══════════════════════════════════════════════════════════════════╝"
echo ""

# ── Per-file coverage ───────────────────────────────────────────────────────
echo "── Per-File Coverage (Critical Crypto Files) ──────────────────────"
echo ""
printf "%-45s %8s %8s %8s %8s %s\n" "FILE" "TOTAL" "HIT" "COV%" "REQ%" "STATUS"
printf "%-45s %8s %8s %8s %8s %s\n" "----" "-----" "---" "----" "----" "------"

CURRENT_FILE=""
FILE_TOTAL=0
FILE_HIT=0

process_file() {
  local file="$1"
  local total="$2"
  local hit="$3"

  if [ "$total" -eq 0 ]; then
    return
  fi

  local cov=$(( hit * 100 / total ))

  # Accumulate global totals
  GLOBAL_TOTAL=$(( GLOBAL_TOTAL + total ))
  GLOBAL_HIT=$(( GLOBAL_HIT + hit ))

  # Check if this is a critical file
  if [ -n "${CRITICAL_FILES[$file]+x}" ]; then
    local threshold="${CRITICAL_FILES[$file]}"
    local status="PASS"
    if [ "$cov" -lt "$threshold" ]; then
      status="FAIL"
      FAILED=$(( FAILED + 1 ))
    else
      PASS_COUNT=$(( PASS_COUNT + 1 ))
    fi
    printf "%-45s %8d %8d %7d%% %7d%% %s\n" "$file" "$total" "$hit" "$cov" "$threshold" "$status"
  fi
}

while IFS= read -r line; do
  case "$line" in
    SF:*)
      # Save previous file
      if [ -n "$CURRENT_FILE" ]; then
        process_file "$CURRENT_FILE" "$FILE_TOTAL" "$FILE_HIT"
      fi
      CURRENT_FILE="${line#SF:}"
      FILE_TOTAL=0
      FILE_HIT=0
      ;;
    DA:*)
      FILE_TOTAL=$(( FILE_TOTAL + 1 ))
      local_count="${line#DA:*,}"
      # Extract execution count (after the comma)
      exec_count="${line##*,}"
      if [ "$exec_count" -gt 0 ] 2>/dev/null; then
        FILE_HIT=$(( FILE_HIT + 1 ))
      fi
      ;;
    end_of_record)
      if [ -n "$CURRENT_FILE" ]; then
        process_file "$CURRENT_FILE" "$FILE_TOTAL" "$FILE_HIT"
      fi
      CURRENT_FILE=""
      FILE_TOTAL=0
      FILE_HIT=0
      ;;
  esac
done < "$LCOV_FILE"

# Handle last file if no trailing end_of_record
if [ -n "$CURRENT_FILE" ]; then
  process_file "$CURRENT_FILE" "$FILE_TOTAL" "$FILE_HIT"
fi

echo ""

# ── Global coverage ─────────────────────────────────────────────────────────
echo "── Global Coverage ──────────────────────────────────────────────────"
echo ""

if [ "$GLOBAL_TOTAL" -eq 0 ]; then
  echo "ERROR: No coverage data found in $LCOV_FILE"
  exit 1
fi

GLOBAL_COV=$(( GLOBAL_HIT * 100 / GLOBAL_TOTAL ))
printf "  Total lines:   %d\n" "$GLOBAL_TOTAL"
printf "  Covered lines: %d\n" "$GLOBAL_HIT"
printf "  Coverage:      %d%%\n" "$GLOBAL_COV"
printf "  Threshold:     %d%%\n" "$GLOBAL_THRESHOLD"

if [ "$GLOBAL_COV" -lt "$GLOBAL_THRESHOLD" ]; then
  echo ""
  echo "  FAIL: Global coverage $GLOBAL_COV% is below minimum $GLOBAL_THRESHOLD%"
  FAILED=$(( FAILED + 1 ))
else
  echo ""
  echo "  PASS: Global coverage $GLOBAL_COV% meets minimum $GLOBAL_THRESHOLD%"
fi

echo ""

# ── Summary ─────────────────────────────────────────────────────────────────
echo "── Summary ──────────────────────────────────────────────────────────"
echo ""

CRITICAL_COUNT="${#CRITICAL_FILES[@]}"
echo "  Critical files checked: $CRITICAL_COUNT"
echo "  Passed: $PASS_COUNT"
echo "  Failed: $FAILED"
echo ""

if [ "$FAILED" -gt 0 ]; then
  echo "RESULT: FAIL — $FAILED threshold violation(s)"
  exit 1
fi

echo "RESULT: PASS — All coverage thresholds met"
exit 0
