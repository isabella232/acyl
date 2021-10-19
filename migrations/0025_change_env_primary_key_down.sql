DROP INDEX IF EXISTS idx_qa_environments_name;
ALTER TABLE qa_environments DROP CONSTRAINT qa_environments_pkey;

ALTER TABLE helm_releases
    DROP CONSTRAINT helm_releases_env_name_fkey;
ALTER TABLE kubernetes_environments
    DROP CONSTRAINT kubernetes_environments_env_name_fkey;
ALTER TABLE event_logs
    DROP CONSTRAINT event_logs_env_name_fkey;

UPDATE event_logs SET env_name = '' WHERE id IN (SELECT id FROM event_logs_empty_names);
INSERT INTO event_logs (SELECT * FROM event_logs_orphans);

DROP TABLE event_logs_empty_names;
DROP TABLE event_logs_orphans;

DROP INDEX IF EXISTS idx_helm_releases_envname;
ALTER TABLE helm_releases
    DROP CONSTRAINT helm_releases_env_id_fkey;
ALTER TABLE helm_releases
    ADD CONSTRAINT helm_releases_env_name_fkey FOREIGN KEY (env_name) REFERENCES qa_environments (name);
ALTER TABLE helm_releases
    DROP COLUMN environment_id;

DROP INDEX IF EXISTS idx_kubernetes_environments_envname;
ALTER TABLE kubernetes_environments
    DROP CONSTRAINT kubernetes_environments_env_id_fkey;
ALTER TABLE kubernetes_environments
    ADD CONSTRAINT kubernetes_environments_env_name_fkey FOREIGN KEY (env_name) REFERENCES qa_environments (name);
ALTER TABLE kubernetes_environments
    DROP COLUMN environment_id;

ALTER TABLE qa_environments DROP COLUMN id;
