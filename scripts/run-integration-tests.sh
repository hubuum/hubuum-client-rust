#!/usr/bin/env bash
set -euo pipefail

SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd -- "${SCRIPT_DIR}/.." && pwd)"
cd "${REPO_ROOT}"

DB_USER="${HUBUUM_INTEGRATION_DB_USER:-hubuum}"
DB_PASSWORD="${HUBUUM_INTEGRATION_DB_PASSWORD:-hubuum_password}"
DB_NAME="${HUBUUM_INTEGRATION_DB_NAME:-hubuum}"
DB_IMAGE="${HUBUUM_INTEGRATION_DB_IMAGE:-postgres:15}"
SERVER_IMAGE="${HUBUUM_INTEGRATION_SERVER_IMAGE:-ghcr.io/hubuum/hubuum-server:no-tls-main}"
STACK_TIMEOUT_SECS="${HUBUUM_INTEGRATION_STACK_TIMEOUT_SECS:-300}"
KEEP_CONTAINERS="${HUBUUM_INTEGRATION_KEEP_CONTAINERS:-0}"

DEFAULT_SEED_SQL="tests/container_integration/seed/init.sql"
SEED_SQL="${HUBUUM_INTEGRATION_SEED_SQL:-${DEFAULT_SEED_SQL}}"
SEED_MODE="auto"

TEST_ARGS=()

usage() {
    cat <<'USAGE'
Usage: scripts/run-integration-tests.sh [options] [-- <test-binary-args...>]

Options:
  --seed <path>      Apply SQL seed file after server startup (fails if file is missing).
  --skip-seed        Do not apply any SQL seed.
  --keep             Keep containers and network after run.
  -h, --help         Show this help text.

Examples:
  scripts/run-integration-tests.sh
  scripts/run-integration-tests.sh --seed tests/container_integration/seed/init.sql
  scripts/run-integration-tests.sh -- --test-threads=1
USAGE
}

while (($# > 0)); do
    case "$1" in
    --seed)
        if (($# < 2)); then
            echo "missing argument for --seed" >&2
            exit 1
        fi
        SEED_SQL="$2"
        SEED_MODE="on"
        shift 2
        ;;
    --skip-seed)
        SEED_MODE="off"
        shift
        ;;
    --keep)
        KEEP_CONTAINERS="1"
        shift
        ;;
    -h | --help)
        usage
        exit 0
        ;;
    --)
        shift
        TEST_ARGS+=("$@")
        break
        ;;
    *)
        TEST_ARGS+=("$1")
        shift
        ;;
    esac
done

suffix="$(date +%s)-$$-${RANDOM}"
NETWORK_NAME="hubuum-it-net-${suffix}"
DB_CONTAINER="hubuum-it-db-${suffix}"
SERVER_CONTAINER="hubuum-it-server-${suffix}"

is_true() {
    case "$1" in
    1 | true | TRUE | True | yes | YES | Yes | on | ON | On) return 0 ;;
    *) return 1 ;;
    esac
}

print_db_diagnostics() {
    echo "DB diagnostics for ${DB_CONTAINER}:"
    docker inspect -f '{{.State.Status}} {{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${DB_CONTAINER}" || true
    docker logs --tail 120 "${DB_CONTAINER}" || true
}

print_server_diagnostics() {
    echo "Server diagnostics for ${SERVER_CONTAINER}:"
    docker inspect -f '{{.State.Status}}' "${SERVER_CONTAINER}" || true
    docker logs --tail 120 "${SERVER_CONTAINER}" || true
}

cleanup() {
    if is_true "${KEEP_CONTAINERS}"; then
        echo "Keeping integration containers/network:"
        echo "  server=${SERVER_CONTAINER}"
        echo "  db=${DB_CONTAINER}"
        echo "  network=${NETWORK_NAME}"
        return
    fi

    docker rm -f "${SERVER_CONTAINER}" "${DB_CONTAINER}" >/dev/null 2>&1 || true
    docker network rm "${NETWORK_NAME}" >/dev/null 2>&1 || true
}
trap cleanup EXIT INT TERM

wait_for_db() {
    local deadline=$((SECONDS + STACK_TIMEOUT_SECS))
    while ((SECONDS < deadline)); do
        local status
        local health
        status="$(docker inspect -f '{{.State.Status}}' "${DB_CONTAINER}" 2>/dev/null || true)"
        health="$(docker inspect -f '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "${DB_CONTAINER}" 2>/dev/null || true)"

        if [[ "${health}" == "healthy" ]]; then
            return 0
        fi

        if [[ "${status}" == "exited" || "${health}" == "unhealthy" ]]; then
            print_db_diagnostics
            return 1
        fi
        sleep 1
    done

    echo "Timed out waiting for DB container health after ${STACK_TIMEOUT_SECS}s."
    print_db_diagnostics
    return 1
}

extract_admin_password() {
    docker logs "${SERVER_CONTAINER}" 2>&1 \
        | grep '"message":"Created admin user"' \
        | sed -n 's/.*"password":"\([^"]*\)".*/\1/p' \
        | tail -n 1
}

wait_for_admin_password() {
    local deadline=$((SECONDS + STACK_TIMEOUT_SECS))
    while ((SECONDS < deadline)); do
        local password
        password="$(extract_admin_password || true)"
        if [[ -n "${password}" ]]; then
            printf '%s' "${password}"
            return 0
        fi
        sleep 1
    done

    echo "Timed out waiting for admin password in server logs after ${STACK_TIMEOUT_SECS}s." >&2
    print_server_diagnostics
    return 1
}

wait_for_server_readiness() {
    local base_url="$1"
    local deadline=$((SECONDS + STACK_TIMEOUT_SECS))

    while ((SECONDS < deadline)); do
        local status
        status="$(curl -sS -o /dev/null -w '%{http_code}' \
            -X POST "${base_url}/api/v0/auth/login" \
            -H 'content-type: application/json' \
            -d '{"username":"__readiness__","password":"__readiness__"}' || true)"

        if [[ "${status}" =~ ^[0-9]{3}$ ]] && [[ "${status}" != "000" ]]; then
            local category="${status:0:1}"
            if [[ "${category}" == "2" || "${category}" == "4" ]]; then
                return 0
            fi
        fi
        sleep 1
    done

    echo "Timed out waiting for server readiness after ${STACK_TIMEOUT_SECS}s." >&2
    print_server_diagnostics
    return 1
}

apply_seed_if_requested() {
    if [[ "${SEED_MODE}" == "off" ]]; then
        echo "Skipping SQL seed (explicitly disabled)."
        return 0
    fi

    if [[ ! -f "${SEED_SQL}" ]]; then
        if [[ "${SEED_MODE}" == "on" ]]; then
            echo "Seed file not found: ${SEED_SQL}" >&2
            return 1
        fi
        echo "Seed file not found, skipping: ${SEED_SQL}"
        return 0
    fi

    echo "Applying SQL seed: ${SEED_SQL}"
    docker exec -i "${DB_CONTAINER}" \
        psql -v ON_ERROR_STOP=1 -U "${DB_USER}" -d "${DB_NAME}" \
        <"${SEED_SQL}"
}

echo "Creating integration Docker network: ${NETWORK_NAME}"
docker network create "${NETWORK_NAME}" >/dev/null

echo "Starting DB container: ${DB_CONTAINER} (${DB_IMAGE})"
docker run -d \
    --name "${DB_CONTAINER}" \
    --network "${NETWORK_NAME}" \
    --health-cmd "pg_isready -U ${DB_USER} -d ${DB_NAME}" \
    --health-interval 1s \
    --health-timeout 5s \
    --health-retries 30 \
    -e "POSTGRES_USER=${DB_USER}" \
    -e "POSTGRES_PASSWORD=${DB_PASSWORD}" \
    -e "POSTGRES_DB=${DB_NAME}" \
    "${DB_IMAGE}" >/dev/null

wait_for_db

DATABASE_URL="postgres://${DB_USER}:${DB_PASSWORD}@${DB_CONTAINER}/${DB_NAME}"

echo "Starting server container: ${SERVER_CONTAINER} (${SERVER_IMAGE})"
docker run -d \
    --name "${SERVER_CONTAINER}" \
    --network "${NETWORK_NAME}" \
    -p "127.0.0.1::8080" \
    -e "HUBUUM_BIND_IP=0.0.0.0" \
    -e "HUBUUM_BIND_PORT=8080" \
    -e "HUBUUM_LOG_LEVEL=debug" \
    -e "HUBUUM_DATABASE_URL=${DATABASE_URL}" \
    -e "DATABASE_URL=${DATABASE_URL}" \
    "${SERVER_IMAGE}" >/dev/null

MAPPED_PORT="$(docker port "${SERVER_CONTAINER}" 8080/tcp | awk -F: 'END {print $NF}')"
if [[ -z "${MAPPED_PORT}" ]]; then
    echo "Failed to resolve mapped server port." >&2
    print_server_diagnostics
    exit 1
fi
BASE_URL="http://127.0.0.1:${MAPPED_PORT}"

ADMIN_PASSWORD="$(wait_for_admin_password)"
wait_for_server_readiness "${BASE_URL}"
apply_seed_if_requested

export HUBUUM_INTEGRATION_BASE_URL="${BASE_URL}"
export HUBUUM_INTEGRATION_ADMIN_PASSWORD="${ADMIN_PASSWORD}"

echo "Running integration tests against external stack: ${BASE_URL}"

CMD=(cargo test --features integration-tests --test container_integration -- --ignored --nocapture)
if ((${#TEST_ARGS[@]} > 0)); then
    CMD+=("${TEST_ARGS[@]}")
fi

"${CMD[@]}"
