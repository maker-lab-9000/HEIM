# Fast-path alert rules — deployment

`alerts.yml` holds the actionable-core alerting rules for the fast path (detection every
Prometheus evaluation interval, investigation dispatch via the n8n **PAM 11 Trigger: Alert poller**
every 5 minutes). The daily LLM workflow is unaffected — it keeps owning trends and reports.

## Deploy (Prometheus runs as the `prometheus` container on the ubuntu-server VM)

1. Copy `alerts.yml` next to your `prometheus.yml` on the host and mount it:

   ```yaml
   # in the prometheus service of your compose file
   volumes:
     - ./prometheus.yml:/etc/prometheus/prometheus.yml:ro
     - ./alerts.yml:/etc/prometheus/alerts.yml:ro
   ```

2. Reference it from `prometheus.yml`:

   ```yaml
   rule_files:
     - /etc/prometheus/alerts.yml
   ```

3. Reload:

   ```bash
   docker restart prometheus
   # or, if started with --web.enable-lifecycle:
   # curl -X POST http://localhost:9090/-/reload
   ```

4. Verify:

   ```bash
   curl -s http://localhost:9090/api/v1/rules | head -c 400; echo      # group "homelab-fast-path"
   curl -s http://localhost:9090/api/v1/alerts                          # {"status":"success",...} (likely no alerts)
   ```

   Or open the Prometheus UI → **Alerts** page: all rules listed, green/inactive.

## How it connects to n8n

The **PAM 11 Trigger: Alert poller** workflow polls `GET /api/v1/alerts` every 5 minutes and:

- turns **firing** alerts (never `pending` — the `for:` durations do the flap suppression)
  into `monitor_incidents` rows (description prefixed `[alert] `),
- dispatches the existing agentic investigation for investigable hosts/categories (same
  Telegram approval flow),
- sends a plain Telegram notification for **critical** alerts that aren't auto-investigable
  (e.g. a dead exporter/host),
- auto-resolves `[alert]`-owned incidents ~10 minutes after the alert stops firing,
- pushes incident/state events to Loki so the Grafana dashboard reflects changes within ~5 min.

## Label contract (don't remove these)

Every rule carries `severity: warning|critical` and `qid: <monitoring_metrics.md query id>`.
The poller builds the incident fingerprint as `host|qid|name` (name from the alert's
`device`/`mountpoint`/`id`/`job` labels), matching the daily LLM path — so both paths share
incident state and never double-investigate.

## Testing end-to-end

Uncomment the `TestAlwaysFiring` rule at the bottom of `alerts.yml`, reload, and within ~5
minutes an incident (`host: unknown`, warning, no Telegram) appears in `monitor_incidents` and
on the Grafana incidents table. Re-comment + reload; it auto-resolves within ~10 minutes.
