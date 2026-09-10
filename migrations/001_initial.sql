CREATE TABLE users (
 id uuid PRIMARY KEY, email text NOT NULL UNIQUE, password_hash text NOT NULL,
 role text NOT NULL DEFAULT 'user' CHECK(role IN ('user','admin')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE tenants (
 id uuid PRIMARY KEY, name text NOT NULL, created_by uuid NOT NULL REFERENCES users(id),
 max_documents integer NOT NULL DEFAULT 100 CHECK(max_documents>0),
 max_storage_bytes bigint NOT NULL DEFAULT 10485760 CHECK(max_storage_bytes>0),
 max_members integer NOT NULL DEFAULT 10 CHECK(max_members>0),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE TABLE memberships (
 tenant_id uuid NOT NULL REFERENCES tenants(id), user_id uuid NOT NULL REFERENCES users(id),
 role text NOT NULL CHECK(role IN ('owner','editor','viewer')),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), PRIMARY KEY(tenant_id,user_id)
);
CREATE TABLE invitations (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), email text NOT NULL,
 role text NOT NULL CHECK(role IN ('editor','viewer')), token_hash text NOT NULL UNIQUE,
 expires_at timestamptz NOT NULL, used_by uuid REFERENCES users(id),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX invitations_tenant ON invitations(tenant_id,created_at DESC);
CREATE TABLE documents (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), title text NOT NULL,
 body text NOT NULL, version integer NOT NULL DEFAULT 1 CHECK(version>0), deleted_at timestamptz,
 created_by uuid NOT NULL REFERENCES users(id), updated_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), UNIQUE(tenant_id,id)
);
CREATE INDEX documents_tenant ON documents(tenant_id,created_at DESC);
CREATE TABLE revisions (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL, document_id uuid NOT NULL, version integer NOT NULL,
 title text NOT NULL, body text NOT NULL, storage_bytes integer NOT NULL CHECK(storage_bytes>0),
 created_by uuid NOT NULL REFERENCES users(id), created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,document_id) REFERENCES documents(tenant_id,id), UNIQUE(tenant_id,document_id,version)
);
CREATE TABLE audit_log (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), actor_id uuid NOT NULL REFERENCES users(id),
 action text NOT NULL, entity_id uuid, details jsonb NOT NULL DEFAULT '{}',
 created_at timestamptz NOT NULL DEFAULT clock_timestamp()
);
CREATE INDEX audit_tenant ON audit_log(tenant_id,created_at DESC);
CREATE TABLE export_jobs (
 id uuid PRIMARY KEY, tenant_id uuid NOT NULL REFERENCES tenants(id), actor_id uuid NOT NULL REFERENCES users(id),
 status text NOT NULL DEFAULT 'queued' CHECK(status IN ('queued','done','rejected')),
 idempotency_key text NOT NULL, result jsonb, error text,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(), finished_at timestamptz,
 UNIQUE(tenant_id,id), UNIQUE(tenant_id,actor_id,idempotency_key)
);
CREATE TABLE export_outbox (
 job_id uuid PRIMARY KEY, tenant_id uuid NOT NULL,
 created_at timestamptz NOT NULL DEFAULT clock_timestamp(),
 FOREIGN KEY(tenant_id,job_id) REFERENCES export_jobs(tenant_id,id) ON DELETE CASCADE
);
CREATE TABLE worker_heartbeats (name text PRIMARY KEY, seen_at timestamptz NOT NULL DEFAULT clock_timestamp());
ALTER TABLE tenants ENABLE ROW LEVEL SECURITY;
ALTER TABLE tenants FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON tenants USING (id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK (id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
CREATE POLICY tenant_discovery ON tenants FOR SELECT USING (EXISTS (SELECT 1 FROM memberships m WHERE m.tenant_id=tenants.id AND m.user_id=NULLIF(current_setting('app.actor_id',true),'')::uuid));
ALTER TABLE memberships ENABLE ROW LEVEL SECURITY;
ALTER TABLE memberships FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON memberships USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
CREATE POLICY self_discovery ON memberships FOR SELECT USING (user_id=NULLIF(current_setting('app.actor_id',true),'')::uuid);
ALTER TABLE invitations ENABLE ROW LEVEL SECURITY;
ALTER TABLE invitations FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON invitations USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
ALTER TABLE documents ENABLE ROW LEVEL SECURITY;
ALTER TABLE documents FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON documents USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
ALTER TABLE revisions ENABLE ROW LEVEL SECURITY;
ALTER TABLE revisions FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON revisions USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
ALTER TABLE audit_log ENABLE ROW LEVEL SECURITY;
ALTER TABLE audit_log FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON audit_log USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
ALTER TABLE export_jobs ENABLE ROW LEVEL SECURITY;
ALTER TABLE export_jobs FORCE ROW LEVEL SECURITY;
CREATE POLICY tenant_scope ON export_jobs USING (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid) WITH CHECK (tenant_id=NULLIF(current_setting('app.tenant_id',true),'')::uuid);
REVOKE ALL ON SCHEMA public FROM PUBLIC;
GRANT USAGE ON SCHEMA public TO tenantdesk_app,tenantdesk_worker;
GRANT SELECT,INSERT,UPDATE ON users TO tenantdesk_app;
GRANT SELECT,INSERT,UPDATE ON tenants,memberships,invitations,documents,export_jobs TO tenantdesk_app;
GRANT DELETE ON memberships,export_jobs TO tenantdesk_app;
GRANT SELECT,INSERT ON revisions,audit_log TO tenantdesk_app;
GRANT INSERT ON export_outbox TO tenantdesk_app;
GRANT SELECT ON worker_heartbeats TO tenantdesk_app;
GRANT SELECT ON tenants,memberships,documents TO tenantdesk_worker;
GRANT SELECT,UPDATE ON export_jobs TO tenantdesk_worker;
GRANT INSERT ON audit_log TO tenantdesk_worker;
GRANT SELECT,DELETE ON export_outbox TO tenantdesk_worker;
GRANT SELECT,INSERT,UPDATE ON worker_heartbeats TO tenantdesk_worker;
GRANT UPDATE(id) ON tenants TO tenantdesk_worker;
GRANT UPDATE ON export_outbox TO tenantdesk_worker;
