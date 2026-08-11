-- 013 — per-rule alert parameters and scope.
--
-- Alert rules had exactly one adjustable number between them: `threshold`,
-- which meant "days" for the two expiry conditions and nothing at all for the
-- other three. Anything you might actually want to watch for on a certificate
-- — a key too short, a SHA-1 signature, a self-signed certificate on a
-- production host, a two-year validity period, an issuer you don't recognise —
-- either had no rule or had no way to say what "too short" meant here.
--
-- params_json holds whatever that particular condition needs, so a condition
-- can take several parameters (weak_key wants a minimum for RSA and a
-- different one for EC) without another column per idea. The condition
-- registry in app/cert/alert_conditions.py declares what each accepts, and the
-- UI renders the fields from that rather than hardcoding them — a new
-- condition needs no frontend change.
ALTER TABLE alert_rules ADD COLUMN params_json TEXT NOT NULL DEFAULT '{}';

-- scope_json narrows which certificates a rule watches: one CA, one source,
-- a name or host pattern. Without it every rule is all-or-nothing, and the
-- rules you'd actually want are the narrow ones — "warn me about short keys on
-- certificates we issued" is useful; "warn me about every short key anywhere
-- in the discovery inventory" is noise on day one and ignored by day three.
ALTER TABLE alert_rules ADD COLUMN scope_json TEXT NOT NULL DEFAULT '{}';

-- Existing rules keep working untouched: threshold is still read as the days
-- value for cert_expiring/ca_expiring when params_json doesn't carry one, so
-- nothing needs migrating and nothing silently changes meaning.
