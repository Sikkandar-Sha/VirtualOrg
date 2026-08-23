-- VirtualOrg, world state.
-- The world is always TRUE and COMPLETE. Loss lives in lens_visibility, never here.

DROP SCHEMA IF EXISTS world CASCADE;
CREATE SCHEMA world;
SET search_path TO world;

-- ---------- people & org ----------
CREATE TABLE department (
  id            text PRIMARY KEY,
  name          text NOT NULL,
  cost_center   text NOT NULL
);

CREATE TABLE person (
  id            text PRIMARY KEY,
  full_name     text NOT NULL,
  email         text NOT NULL,
  department_id text NOT NULL REFERENCES department(id),
  title         text NOT NULL,
  employment    text NOT NULL CHECK (employment IN ('employee','contractor')),
  started_on    date NOT NULL,
  ended_on      date                       -- non-null = leaver
);

-- ---------- identity ----------
CREATE TABLE account (
  id            text PRIMARY KEY,
  person_id     text NOT NULL REFERENCES person(id),
  system        text NOT NULL,
  username      text NOT NULL,
  privileged    boolean NOT NULL DEFAULT false,
  created_on    date NOT NULL,
  disabled_on   date                       -- NULL after person.ended_on = orphaned access
);

CREATE TABLE access_group (
  id          text PRIMARY KEY,
  name        text NOT NULL,
  system      text NOT NULL,
  privileged  boolean NOT NULL DEFAULT false
);

CREATE TABLE group_membership (
  group_id   text NOT NULL REFERENCES access_group(id),
  account_id text NOT NULL REFERENCES account(id),
  granted_on date NOT NULL,
  revoked_on date,                     -- NULL after person.ended_on = retained access
  PRIMARY KEY (group_id, account_id)
);

-- ---------- assets ----------
CREATE TABLE asset (
  id              text PRIMARY KEY,
  hostname        text NOT NULL,           -- LT-4471
  fqdn            text NOT NULL,           -- lt-4471.corp.local
  asset_tag       text NOT NULL,           -- AT-900001
  ip              inet NOT NULL,           -- recycled over time
  kind            text NOT NULL CHECK (kind IN ('endpoint','server','cloud')),
  os_family       text NOT NULL,
  os_version      text NOT NULL,
  owner_person_id text REFERENCES person(id),
  criticality     text NOT NULL CHECK (criticality IN ('low','medium','high','critical')),
  procured_on     date NOT NULL,
  decommissioned_on date
);

CREATE TABLE software (
  id        text PRIMARY KEY,
  name      text NOT NULL,
  publisher text NOT NULL,
  version   text NOT NULL,
  eol_on    date                       -- past = running unsupported software
);

CREATE TABLE software_install (
  asset_id     text NOT NULL REFERENCES asset(id),
  software_id  text NOT NULL REFERENCES software(id),
  installed_on date NOT NULL,
  PRIMARY KEY (asset_id, software_id)
);

-- ---------- applications & services ----------
CREATE TABLE application (
  id              text PRIMARY KEY,
  name            text NOT NULL,
  owner_person_id text REFERENCES person(id),
  criticality     text NOT NULL
);

CREATE TABLE business_service (
  id              text PRIMARY KEY,
  name            text NOT NULL,
  criticality     text NOT NULL CHECK (criticality IN ('tier3','tier2','tier1')),
  owner_person_id text REFERENCES person(id),
  daily_revenue   numeric(12,2) NOT NULL
);

CREATE TABLE application_asset (
  application_id text NOT NULL REFERENCES application(id),
  asset_id       text NOT NULL REFERENCES asset(id),
  PRIMARY KEY (application_id, asset_id)
);

CREATE TABLE business_process (
  id              text PRIMARY KEY,
  name            text NOT NULL,
  owner_person_id text REFERENCES person(id),
  criticality     text NOT NULL CHECK (criticality IN ('low','medium','high','critical')),
  rto_hours       int NOT NULL          -- recovery time objective
);

CREATE TABLE process_service (
  process_id text NOT NULL REFERENCES business_process(id),
  service_id text NOT NULL REFERENCES business_service(id),
  PRIMARY KEY (process_id, service_id)
);

CREATE TABLE service_dependency (
  service_id     text NOT NULL REFERENCES business_service(id),
  application_id text NOT NULL REFERENCES application(id),
  PRIMARY KEY (service_id, application_id)
);

-- ---------- governance ----------
CREATE TABLE framework (
  id      text PRIMARY KEY,
  name    text NOT NULL,
  version text NOT NULL
);

CREATE TABLE requirement (
  id           text PRIMARY KEY,
  framework_id text NOT NULL REFERENCES framework(id),
  ref          text NOT NULL,
  title        text NOT NULL
);

CREATE TABLE control (
  id              text PRIMARY KEY,
  ref             text NOT NULL,
  title           text NOT NULL,
  owner_person_id text REFERENCES person(id),   -- may point at a leaver: conflict
  test_frequency  text NOT NULL CHECK (test_frequency IN ('monthly','quarterly','annual')),
  automated       boolean NOT NULL DEFAULT false
);

-- coverage strength, NOT a boolean link (#4.2)
CREATE TABLE control_mapping (
  control_id     text NOT NULL REFERENCES control(id),
  requirement_id text NOT NULL REFERENCES requirement(id),
  coverage       numeric(3,2) NOT NULL CHECK (coverage > 0 AND coverage <= 1),
  PRIMARY KEY (control_id, requirement_id)
);

-- Crosswalks are imperfect on purpose: two frameworks rarely say the same thing,
-- and pretending they do is how a control failure moves the wrong number. (#4.2)
CREATE TABLE requirement_crosswalk (
  source_requirement_id text NOT NULL REFERENCES requirement(id),
  target_requirement_id text NOT NULL REFERENCES requirement(id),
  equivalence   numeric(3,2) NOT NULL CHECK (equivalence > 0 AND equivalence <= 1),
  PRIMARY KEY (source_requirement_id, target_requirement_id)
);

CREATE TABLE policy (
  id               text PRIMARY KEY,
  ref              text NOT NULL,
  title            text NOT NULL,
  owner_person_id  text REFERENCES person(id),
  approved_on      date NOT NULL,
  review_period_days int NOT NULL DEFAULT 365
);

CREATE TABLE policy_control (
  policy_id  text NOT NULL REFERENCES policy(id),
  control_id text NOT NULL REFERENCES control(id),
  PRIMARY KEY (policy_id, control_id)
);

-- An approved deviation. Past expires_on and still relied upon is a conflict the
-- GRC platform will not surface on its own.
CREATE TABLE control_exception (
  id          text PRIMARY KEY,
  control_id  text NOT NULL REFERENCES control(id),
  reason      text NOT NULL,
  approved_by text REFERENCES person(id),
  approved_on date NOT NULL,
  expires_on  date NOT NULL,
  status      text NOT NULL CHECK (status IN ('active','expired','withdrawn'))
);

CREATE TABLE control_test (
  id          text PRIMARY KEY,
  control_id  text NOT NULL REFERENCES control(id),
  tested_on   date NOT NULL,
  result      text NOT NULL CHECK (result IN ('effective','partial','ineffective')),
  tester_id   text REFERENCES person(id)
);

CREATE TABLE audit (
  id           text PRIMARY KEY,
  name         text NOT NULL,
  framework_id text NOT NULL REFERENCES framework(id),
  started_on   date NOT NULL,
  ended_on     date
);

CREATE TABLE finding (
  id         text PRIMARY KEY,
  audit_id   text NOT NULL REFERENCES audit(id),
  control_id text NOT NULL REFERENCES control(id),
  title      text NOT NULL,
  severity   text NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  raised_on  date NOT NULL,
  due_on     date NOT NULL,
  closed_on  date,
  status     text NOT NULL CHECK (status IN ('open','overdue','closed'))
);

-- Binary evidence. The bytes are generated on read; the world stores only the
-- metadata a GRC platform would hold. (#5 "binary evidence retrieval")
CREATE TABLE attachment (
  id          text PRIMARY KEY,
  finding_id  text NOT NULL REFERENCES finding(id),
  filename    text NOT NULL,
  media_type  text NOT NULL,
  size_bytes  int NOT NULL,
  uploaded_on  date NOT NULL,
  -- Seeds the deterministic body. The digest the API advertises is computed from
  -- the bytes actually served, so a connector that verifies it succeeds.
  content_seed text NOT NULL
);

CREATE TABLE risk (
  id               text PRIMARY KEY,
  ref              text NOT NULL,
  title            text NOT NULL,
  category         text NOT NULL,
  inherent_score   numeric(4,1) NOT NULL,
  appetite         numeric(4,1) NOT NULL,
  owner_person_id  text REFERENCES person(id),
  last_reviewed_on date NOT NULL,
  review_period_days int NOT NULL DEFAULT 90
);

CREATE TABLE risk_control (
  risk_id      text NOT NULL REFERENCES risk(id),
  control_id   text NOT NULL REFERENCES control(id),
  contribution numeric(3,2) NOT NULL,
  PRIMARY KEY (risk_id, control_id)
);

CREATE TABLE risk_treatment (
  id           text PRIMARY KEY,
  risk_id      text NOT NULL REFERENCES risk(id),
  strategy     text NOT NULL CHECK (strategy IN ('accept','mitigate','transfer','avoid')),
  description  text NOT NULL,
  owner_person_id text REFERENCES person(id),
  target_date  date NOT NULL,
  completed_on date,
  status       text NOT NULL CHECK (status IN ('planned','in_progress','complete','overdue'))
);

CREATE TABLE risk_service (
  risk_id    text NOT NULL REFERENCES risk(id),
  service_id text NOT NULL REFERENCES business_service(id),
  PRIMARY KEY (risk_id, service_id)
);

-- ---------- security posture ----------
CREATE TABLE detection_rule (
  id      text PRIMARY KEY,
  name    text NOT NULL,
  severity text NOT NULL
);

CREATE TABLE alert (
  id          text PRIMARY KEY,
  rule_id     text NOT NULL REFERENCES detection_rule(id),
  asset_id    text REFERENCES asset(id),
  person_id   text REFERENCES person(id),
  severity    text NOT NULL,
  occurred_at timestamptz NOT NULL
);

CREATE TABLE incident (
  id            text PRIMARY KEY,
  ref           text NOT NULL,
  title         text NOT NULL,
  category      text NOT NULL,
  severity      int NOT NULL CHECK (severity BETWEEN 1 AND 4),
  service_id    text REFERENCES business_service(id),
  opened_at     timestamptz NOT NULL,
  closed_at     timestamptz,
  stated_impact text NOT NULL         -- may contradict service tier: conflict
);

CREATE TABLE vulnerability (
  id             text PRIMARY KEY,
  asset_id       text NOT NULL REFERENCES asset(id),
  cve            text NOT NULL,
  cvss           numeric(3,1) NOT NULL,
  discovered_on  date NOT NULL,
  remediated_on  date
);

CREATE TABLE misconfiguration (
  id            text PRIMARY KEY,
  asset_id      text NOT NULL REFERENCES asset(id),
  baseline_ref  text NOT NULL,          -- e.g. CIS-1.2.3
  title         text NOT NULL,
  severity      text NOT NULL CHECK (severity IN ('low','medium','high','critical')),
  detected_on   date NOT NULL,
  remediated_on date
);

-- ---------- evidence: the ground-truth attribution layer (#7 Attribution) ----------
CREATE TABLE evidence (
  id          text PRIMARY KEY,
  kind        text NOT NULL CHECK (kind IN ('alert','control_test','finding','incident','vulnerability')),
  source_ref  text NOT NULL,          -- id in the originating table
  control_id  text NOT NULL REFERENCES control(id),   -- TRUE attribution
  strength    numeric(3,2) NOT NULL,
  observed_at timestamptz NOT NULL,
  is_trap     boolean NOT NULL DEFAULT false          -- topically related, NOT evidence
);

-- ---------- lenses: where all loss lives (#5) ----------
CREATE TABLE lens (
  id               text PRIMARY KEY,
  vendor           text NOT NULL,
  category         text NOT NULL,
  coverage         numeric(3,2) NOT NULL,
  latency_minutes  int NOT NULL,
  identifier_style text NOT NULL,     -- fqdn | hostname | ip | asset_tag
  retention_days   int NOT NULL,
  blind_spot       text NOT NULL
);

-- materialises coverage + naming: what this lens can see and what it calls it
CREATE TABLE lens_visibility (
  lens_id     text NOT NULL REFERENCES lens(id),
  entity_kind text NOT NULL,
  entity_id   text NOT NULL,
  external_id text NOT NULL,          -- the identifier THIS lens uses
  last_seen   timestamptz NOT NULL,   -- staleness
  PRIMARY KEY (lens_id, entity_kind, entity_id)
);

-- ---------- ground truth: the assertion catalogue, materialised (#7) ----------
CREATE TABLE expectation (
  id          text PRIMARY KEY,
  family      text NOT NULL CHECK (family IN ('attribution','conflict','degradation','absence')),
  subject_kind text NOT NULL,
  subject_id  text NOT NULL,
  claim       text NOT NULL,
  detail      jsonb NOT NULL DEFAULT '{}'
);

CREATE TABLE world_meta (
  key   text PRIMARY KEY,
  value text NOT NULL
);

CREATE INDEX ON alert (occurred_at);
CREATE INDEX ON alert (rule_id);
CREATE INDEX ON incident (opened_at);
CREATE INDEX ON finding (control_id);
CREATE INDEX ON evidence (control_id);
CREATE INDEX ON attachment (finding_id);
CREATE INDEX ON software_install (asset_id);
CREATE INDEX ON misconfiguration (asset_id);
CREATE INDEX ON group_membership (account_id);
CREATE INDEX ON lens_visibility (lens_id, entity_kind);
