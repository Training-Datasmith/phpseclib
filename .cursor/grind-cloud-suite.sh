#!/usr/bin/env bash
# Training-Datasmith cloud grind: ParaTest + CI-style SSH functional fixture + JUnit gate.
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

JUNIT_DATE="${JUNIT_DATE:-$(date -u +%Y%m%d)}"
JUNIT_PATH="${JUNIT_PATH:-phpunit-remote-${JUNIT_DATE}.xml}"

composer install --classmap-authoritative --no-interaction --no-cache --ignore-platform-req=php

# shellcheck source=/dev/null
source tests/setup-functional-ssh.sh

vendor/bin/paratest \
    --verbose \
    --configuration=tests/phpunit.xml \
    --runner=WrapperRunner \
    --log-junit="$JUNIT_PATH"

php -r '
$path = $argv[1];
if (!is_file($path)) {
    fwrite(STDERR, "Missing JUnit: $path\n");
    exit(1);
}
$xml = @simplexml_load_file($path);
if ($xml === false) {
    fwrite(STDERR, "Invalid JUnit XML: $path\n");
    exit(1);
}
$failures = (int) ($xml["failures"] ?? 0);
$errors = (int) ($xml["errors"] ?? 0);
if ($failures !== 0 || $errors !== 0) {
    fwrite(STDERR, "JUnit gate failed: failures=$failures errors=$errors ($path)\n");
    exit(1);
}
echo "JUnit gate OK: failures=0 errors=0 ($path)\n";
' "$JUNIT_PATH"
