-- Remove the AI Assistant feature entirely.
--
-- The in-app assistant is being withdrawn rather than migrated: the
-- replacement will arrive later as a separate suite app, with its own
-- interface and its own configuration. Leaving these rows behind would
-- strand encrypted third-party API keys in the database with no code left
-- that reads them, so they are deleted here rather than orphaned.
--
-- Matched by PATTERN rather than by an enumerated key list, deliberately.
-- Key names drifted between apps as the assistant was built out (pktPCAP
-- used anthropic_key/openai_key where its siblings used anthropic_api_key
-- /openai_api_key), so an enumerated list silently purges nothing on an
-- install whose names don't happen to match. Anything AI-related goes,
-- whatever it is called.
--
-- ai_local_providers additionally holds a per-entry api_key inside its JSON
-- blob, so it goes for the same reason.
DELETE FROM settings WHERE
       key LIKE 'ai\_%' ESCAPE '\'
    OR key LIKE '%anthropic%'
    OR key LIKE '%openai%'
    OR key LIKE '%ollama%'
    OR key LIKE '%claude%';
