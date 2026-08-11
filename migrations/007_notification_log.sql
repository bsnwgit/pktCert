-- 007 — delivery log for alert notifications.
--
-- alert_rules has carried a `channels` list since 002, the Alerts UI has let
-- you pick channels, and Settings has been able to send test messages on
-- each of them — but nothing ever dispatched a real alert. Every firing rule
-- wrote an alert_events row and stopped there, so a certificate-expiry alert
-- with `email` selected notified precisely nobody, silently. app/cert/
-- alert_engine.py now dispatches, and records the outcome here.
--
-- Same shape as the equivalent table in the rest of the suite (pktflow,
-- pktlog) so the retention/cleanup behaviour and any future reporting stay
-- consistent across apps.
--
-- ON DELETE CASCADE matters: run_cleanup_once() trims resolved alert_events
-- past their retention window, and without the cascade those deletes would
-- either fail (when foreign_keys=ON, as on every request connection) or
-- strand orphan rows here.
CREATE TABLE IF NOT EXISTS notification_log (
    id       INTEGER PRIMARY KEY AUTOINCREMENT,
    event_id INTEGER NOT NULL REFERENCES alert_events(id) ON DELETE CASCADE,
    channel  TEXT NOT NULL,          -- inapp | email | slack | pagerduty | webhook | tracecat
    status   TEXT NOT NULL,          -- sent | failed | skipped
    error    TEXT,
    sent_at  TEXT NOT NULL DEFAULT (datetime('now'))
);
CREATE INDEX IF NOT EXISTS idx_notif_log_event ON notification_log(event_id);
CREATE INDEX IF NOT EXISTS idx_notif_log_sent ON notification_log(sent_at);
