#!/bin/bash
# Record real runs of Claude Code and Codex and check what Quena makes of them: every LLM call
# read with model, tokens and price, one conversation per run, the system prompt taken apart.
# Run it after updates of the agents, whose request formats change between versions.
#
#   tools/agent-check/run.sh            both agents
#   tools/agent-check/run.sh claude     one of them
#   tools/agent-check/run.sh --keep …   keep the captures (they hold your credentials)
#
# The agents must be installed and logged in; a run costs a few cents of tokens. Quena runs as
# quena-cli reverse proxy (no window, no system proxy, no keychain): the agents are pointed at
# it with ANTHROPIC_BASE_URL (Claude Code) and chatgpt_base_url / openai_base_url (Codex).
set -eu
here="$(cd "$(dirname "$0")" && pwd)"
repo="$(cd "$here/../.." && pwd)"
keep=0
agents=()
for a in "$@"; do
  case "$a" in
    --keep) keep=1 ;;
    claude | codex) agents+=("$a") ;;
    *) echo "usage: $0 [--keep] [claude] [codex]" >&2; exit 2 ;;
  esac
done
[ ${#agents[@]} -eq 0 ] && agents=(claude codex)
out="$(mktemp -d "${TMPDIR:-/tmp}/quena-agent-check.XXXXXX")"
if [ $keep -eq 0 ]; then
  trap 'rm -rf "$out"' EXIT
fi
prompt="Read README.md and stats.py in this folder, then say in one sentence what median() gets wrong. Do not change any file."

cargo build -q -p quena-cli --manifest-path "$repo/Cargo.toml"
cli="$repo/target/debug/quena-cli"

# record NAME PORT TARGET COMMAND…: run COMMAND in the sample project while quena-cli forwards
# PORT to TARGET and records into $out/NAME.saz.
record() {
  local name=$1 port=$2 target=$3
  shift 3
  "$cli" reverse --route "$name=$port=$target" --save "$out/$name.saz" --duration 600 -q > "$out/$name.log" 2>&1 &
  local pid=$!
  for _ in $(seq 1 50); do
    (exec 3<>"/dev/tcp/127.0.0.1/$port") 2>/dev/null && break
    sleep 0.1
  done
  echo "── $name"
  (cd "$here/project" && "$@" < /dev/null) || echo "   ($name ended with an error)"
  kill -TERM $pid
  wait $pid || true
}

captures=()
for a in "${agents[@]}"; do
  case "$a" in
    claude)
      command -v claude > /dev/null || { echo "claude is not installed" >&2; exit 2; }
      record claude 18911 https://api.anthropic.com \
        env -u CLAUDECODE -u CLAUDE_CODE_ENTRYPOINT ANTHROPIC_BASE_URL=http://127.0.0.1:18911 \
        claude -p "$prompt" --allowedTools Read
      ;;
    codex)
      command -v codex > /dev/null || { echo "codex is not installed" >&2; exit 2; }
      record codex 18912 https://chatgpt.com \
        codex exec --skip-git-repo-check -s read-only \
        -c 'chatgpt_base_url="http://127.0.0.1:18912/backend-api/"' \
        -c 'openai_base_url="http://127.0.0.1:18912/backend-api/codex"' "$prompt"
      ;;
  esac
  captures+=("$out/$a.saz")
done

list=$(IFS=,; echo "${captures[*]}")
echo "── check"
AGENT_CHECK="$list" cargo test -q -p quena-app-core --manifest-path "$repo/Cargo.toml" --test agent_check -- --ignored --nocapture
if [ $keep -eq 1 ]; then
  echo "Captures in $out (they hold your credentials: delete them when done)."
fi
