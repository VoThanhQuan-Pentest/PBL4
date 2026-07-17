#!/usr/bin/env bash

set -Eeuo pipefail

PROJECT_ROOT="$(pwd -P)"
SKILLS_DIR="$PROJECT_ROOT/.agents/skills"
BACKUP_DIR="$PROJECT_ROOT/.agents/skills-backup/$(date +%Y%m%d-%H%M%S)"
TEMP_DIR="$(mktemp -d -t codex-skills-XXXXXX)"

trap 'rm -rf "$TEMP_DIR"' EXIT

info() {
    printf '\n\033[1;34m==> %s\033[0m\n' "$*"
}

ok() {
    printf '\033[1;32m[OK]\033[0m %s\n' "$*"
}

warn() {
    printf '\033[1;33m[SKIP]\033[0m %s\n' "$*" >&2
}

fail() {
    printf '\033[1;31m[ERROR]\033[0m %s\n' "$*" >&2
    exit 1
}

command -v git >/dev/null 2>&1 ||
    fail "Không tìm thấy git."

command -v python3 >/dev/null 2>&1 ||
    fail "Không tìm thấy python3."

[[ -d "$PROJECT_ROOT" ]] ||
    fail "Không tìm thấy project."

mkdir -p "$SKILLS_DIR" "$BACKUP_DIR"

declare -A REPOS=(
    [anthropic]="https://github.com/anthropics/skills.git"
    [vercel]="https://github.com/vercel-labs/agent-skills.git"
    [spring]="https://github.com/Amplicode/spring-skills.git"
    [addy]="https://github.com/addyosmani/agent-skills.git"
    [context]="https://github.com/muratcankoylan/Agent-Skills-for-Context-Engineering.git"
)

declare -A REPO_PATHS
INSTALLED=()
SKIPPED=()

info "Project: $PROJECT_ROOT"
info "Nơi cài skill: $SKILLS_DIR"

clone_repo() {
    local key="$1"
    local destination="$TEMP_DIR/$key"

    info "Tải repository: ${REPOS[$key]}"

    if git clone \
        --depth 1 \
        --filter=blob:none \
        --no-tags \
        "${REPOS[$key]}" \
        "$destination"; then

        REPO_PATHS["$key"]="$destination"
        ok "Đã tải $key"
    else
        warn "Không tải được repository $key"
        REPO_PATHS["$key"]=""
    fi
}

for repo in anthropic vercel spring addy context; do
    clone_repo "$repo"
done

find_skill() {
    local repo_dir="$1"
    local skill_name="$2"

    find "$repo_dir" \
        -type f \
        -path "*/$skill_name/SKILL.md" \
        -print \
        -quit
}

audit_skill() {
    local skill_dir="$1"
    local skill_name="$2"
    local audit_output="$TEMP_DIR/audit-$skill_name.txt"

    : > "$audit_output"

    [[ -f "$skill_dir/SKILL.md" ]] || {
        warn "$skill_name thiếu SKILL.md"
        return 1
    }

    if find "$skill_dir" -type l -print -quit | grep -q .; then
        warn "$skill_name chứa symbolic link"
        return 1
    fi

    local dangerous_pattern
    dangerous_pattern='curl.+\|.+(sh|bash)|wget.+\|.+(sh|bash)|sudo[[:space:]]|rm[[:space:]]+-rf[[:space:]]+/|/etc/shadow|/etc/sudoers|crontab|systemctl[[:space:]]+(enable|start)|disable.{0,30}sandbox|bypass.{0,30}approval|ignore.{0,30}(previous|system|developer).{0,30}instruction|\.ssh/|\.gnupg/'

    if grep -RInEI \
        "$dangerous_pattern" \
        "$skill_dir" \
        --include='SKILL.md' \
        --include='*.md' \
        --include='*.sh' \
        --include='*.bash' \
        --include='*.py' \
        --include='*.js' \
        --include='*.ts' \
        --include='package.json' \
        --include='hooks.json' \
        --include='.mcp.json' \
        > "$audit_output" 2>/dev/null; then

        warn "$skill_name chứa nội dung cần kiểm tra thủ công:"
        cat "$audit_output" >&2
        return 1
    fi

    return 0
}

install_skill() {
    local repo_key="$1"
    local skill_name="$2"
    local repo_dir="${REPO_PATHS[$repo_key]:-}"

    if [[ -z "$repo_dir" || ! -d "$repo_dir" ]]; then
        warn "$skill_name vì repository $repo_key không có"
        SKIPPED+=("$skill_name: repository unavailable")
        return
    fi

    info "Kiểm tra skill: $skill_name"

    local skill_file
    skill_file="$(find_skill "$repo_dir" "$skill_name")"

    if [[ -z "$skill_file" ]]; then
        warn "Không tìm thấy $skill_name"
        SKIPPED+=("$skill_name: not found")
        return
    fi

    local source_dir
    source_dir="$(dirname "$skill_file")"

    if ! audit_skill "$source_dir" "$skill_name"; then
        SKIPPED+=("$skill_name: audit failed")
        return
    fi

    local destination="$SKILLS_DIR/$skill_name"

    if [[ -e "$destination" || -L "$destination" ]]; then
        info "Sao lưu phiên bản cũ của $skill_name"
        mv "$destination" "$BACKUP_DIR/$skill_name"
    fi

    mkdir -p "$destination"
    cp -a "$source_dir/." "$destination/"

    local commit
    commit="$(git -C "$repo_dir" rev-parse HEAD)"

    cat > "$destination/INSTALL-SOURCE.txt" <<EOF
Skill: $skill_name
Repository: ${REPOS[$repo_key]}
Commit: $commit
Installed: $(date --iso-8601=seconds)
Scope: project
Project: $PROJECT_ROOT
Scripts executed during installation: no
EOF

    INSTALLED+=("$skill_name")
    ok "Đã cài $skill_name"
}

# Frontend
install_skill anthropic frontend-design
install_skill vercel react-best-practices
install_skill vercel web-design-guidelines

# Spring Boot backend
install_skill spring spring-explore
install_skill spring spring-planning
install_skill spring spring-data-jpa

# API, review và security
install_skill addy api-and-interface-design
install_skill addy code-review-and-quality
install_skill addy security-and-hardening

# Context và token
install_skill context context-compression
install_skill context context-optimization

info "Tạo chính sách giảm context/token trong AGENTS.md"

python3 - "$PROJECT_ROOT/AGENTS.md" <<'PY'
from pathlib import Path
import sys

path = Path(sys.argv[1])

start = "<!-- CODEX-CONTEXT-POLICY:START -->"
end = "<!-- CODEX-CONTEXT-POLICY:END -->"

block = """<!-- CODEX-CONTEXT-POLICY:START -->
## Codex context and quality policy

### Context efficiency

- Tìm kiếm bằng `rg`, `git grep` hoặc tên file trước khi mở nhiều file.
- Chỉ đọc file liên quan trực tiếp đến nhiệm vụ và dependency gần nhất.
- Không quét toàn bộ repository khi chưa có lý do rõ ràng.
- Không đọc lại file chưa thay đổi nếu không cần xác minh.
- Tóm tắt log dài, giữ lỗi có thể xử lý đầu tiên và nguyên nhân gốc.
- Không tạo tài liệu hoặc kế hoạch dài trừ khi người dùng yêu cầu.
- Không dùng subagent cho nhiệm vụ một agent có thể xử lý tin cậy.
- Chỉ kích hoạt số lượng skill tối thiểu cần cho nhiệm vụ.
- Sau mỗi giai đoạn, giữ lại quyết định, file đã sửa, test và lỗi còn lại.

### Implementation quality

- Tuân thủ kiến trúc và convention hiện có của project.
- Không tạo kiến trúc song song khi có thể mở rộng code hiện tại.
- Thực hiện thay đổi nhỏ, có thể kiểm tra và dễ hoàn tác.
- Chạy test liên quan trước khi chạy toàn bộ test suite.
- Kiểm tra `git diff` trước khi kết thúc.
- Không tự động thay đổi secret, credential hoặc file môi trường.
- Không chạy script từ skill nếu chưa kiểm tra nội dung và sự cần thiết.

### Skill selection

- Dùng `frontend-design` cho thiết kế giao diện và visual direction.
- Dùng `web-design-guidelines` để review UI, responsive và accessibility.
- Dùng `react-best-practices` chỉ khi phần đang sửa sử dụng React hoặc Next.js.
- Dùng các Spring skill cho backend Spring Boot.
- Dùng `api-and-interface-design` cho API contract và error semantics.
- Dùng `security-and-hardening` cho thay đổi liên quan bảo mật.
- Dùng context skill khi conversation, log hoặc repository context quá lớn.
<!-- CODEX-CONTEXT-POLICY:END -->"""

existing = path.read_text(encoding="utf-8") if path.exists() else ""

if start in existing and end in existing:
    before = existing.split(start, 1)[0].rstrip()
    after = existing.split(end, 1)[1].lstrip()

    parts = [part for part in (before, block, after) if part]
    output = "\n\n".join(parts)
else:
    output = existing.rstrip()

    if output:
        output += "\n\n"

    output += block

path.write_text(output.rstrip() + "\n", encoding="utf-8")
PY

ok "Đã cập nhật AGENTS.md"

MANIFEST="$SKILLS_DIR/INSTALLED-SKILLS.md"

{
    echo "# Installed Codex skills"
    echo
    echo "Generated: $(date --iso-8601=seconds)"
    echo
    echo "## Installed"

    if [[ "${#INSTALLED[@]}" -eq 0 ]]; then
        echo "- None"
    else
        for skill in "${INSTALLED[@]}"; do
            echo "- \`$skill\`"
        done
    fi

    echo
    echo "## Skipped"

    if [[ "${#SKIPPED[@]}" -eq 0 ]]; then
        echo "- None"
    else
        for skill in "${SKIPPED[@]}"; do
            echo "- $skill"
        done
    fi
} > "$MANIFEST"

if ! find "$BACKUP_DIR" -mindepth 1 -print -quit | grep -q .; then
    rmdir "$BACKUP_DIR" 2>/dev/null || true
fi

info "Kết quả"

printf '\nSkill đã cài:\n'

if [[ "${#INSTALLED[@]}" -eq 0 ]]; then
    printf '  Không có\n'
else
    printf '  - %s\n' "${INSTALLED[@]}"
fi

printf '\nSkill bị bỏ qua:\n'

if [[ "${#SKIPPED[@]}" -eq 0 ]]; then
    printf '  Không có\n'
else
    printf '  - %s\n' "${SKIPPED[@]}"
fi

printf '\nManifest:\n  %s\n' "$MANIFEST"

if git -C "$PROJECT_ROOT" rev-parse --is-inside-work-tree \
    >/dev/null 2>&1; then

    printf '\nGit status:\n'
    git -C "$PROJECT_ROOT" status --short -- \
        .agents \
        AGENTS.md \
        .codex-tools || true
fi

printf '\nHoàn tất. Mở Codex tại project và chạy /skills\n'
