# Flare Security Monitor

JavaFX 21 desktop client for the Spring Boot SIEM API. The client stores its
session cookies only in memory, fetches a CSRF token before state-changing
requests and accepts Administrator, Security analyst (legacy L1), SOC L1 or
SOC L2 accounts.
Every state-changing request fetches a fresh CSRF token. Sign out revokes the
server session and clears the in-memory cookie jar; if the server cannot confirm
revocation, the client still clears its cookies and displays a warning.

For the prepared local SOC L1/L2 presentation, including dedicated
demo credentials, startup, escalation, session revocation and troubleshooting,
use [the local demonstration runbook](../docs/LOCAL_SOC_DEMO_L1_L2.md). It reuses
the existing `flare-otp-local` stack; do not start the full ELK stack on the same
port at the same time. Its incidents are explicitly labelled workflow fixtures,
not trained-model detections.

## Development

```bash
mvn javafx:run
```

The login contains only the wordmark and credentials. Server origin is selected
from `-Dflare.soc.serverOrigin`, then `FLARE_SOC_SERVER_ORIGIN`, then
`http://127.0.0.1:8089`. Remote origins require HTTPS. For the existing V40
presentation before cutover, set the property to `http://127.0.0.1:8088`.

The unified local topology uses `docker-compose.siem-local.yml` with the existing
OTP project. Follow [the upgrade gates](../docs/LOCAL_SIEM_UPGRADE.md); do not start
a second application stack or reuse an Elasticsearch volume with two writers.

There are exactly five navigation entries: Dashboard, Incident queue, Block IP,
History, and GeoIP & IP intelligence. Open a selected incident with double click,
Enter or **Mở xử lý**. A single nonmodal window is reused; unsaved notes require
Save, Discard or Cancel. ELK events have expandable Fields/JSON views; workflow,
model context and notes remain separately labelled.

Create a user with role `Security analyst` through the existing Administrator
user-management API/UI. Public registration always remains a customer account.

## Security overview

Overview shows donut charts for severity, workflow status and automatic
classification over the selected one-hour, 24-hour or seven-day range. Clicking
a slice or legend opens the incident queue with the corresponding server-side
filter. The priority table always considers every open incident and orders
investigation candidates by score, workflow state and recency.

The incident queue defaults to open incidents in priority order. It supports
severity, status and classification filters, text search, latest/priority sort,
50-row pages and a one-click reset back to the open priority queue.

## Linux package

Run `./scripts/package-linux.sh` with Maven and a JDK that includes `jpackage`
(JDK 21 is the supported baseline). Each build gets a new `target/dist-release-*`
directory, preserving older packages and Maven output. No password or server
credential is embedded in the package.

Current local application (25 October 2026):
`target/dist-release.3mu5BWLb/FlareSecurityMonitor/bin/FlareSecurityMonitor`.
The local API is `http://127.0.0.1:8089`. Login accounts are listed once in
`../TAI_KHOAN_DANG_NHAP.local.md` (owner-readable and excluded from Git).

Incident windows have two primary tabs: log information with response controls
below it, and the original ELK event timeline. SOC handling history appears for
closed cases. Use the window maximize control or **Toàn màn hình / F11**.
The accepted model baseline and OTP remain authoritative; the candidate is SHADOW.
