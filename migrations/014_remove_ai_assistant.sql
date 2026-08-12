-- Remove the AI Assistant feature entirely.
--
-- The in-app assistant is being withdrawn rather than migrated: the
-- replacement will arrive later as a separate suite app, with its own
-- interface and its own configuration. Leaving these rows behind would
-- strand encrypted third-party API keys in the database with no code left
-- that reads them, so they are deleted here rather than orphaned.
--
-- ai_local_providers additionally holds a per-entry api_key inside its JSON
-- blob, so it goes for the same reason.
DELETE FROM settings WHERE key IN (
    'ai_provider_ollama_enabled',
    'ai_provider_ollama_base_url',
    'ai_provider_ollama_model',
    'ai_local_providers',
    'ai_provider_anthropic_enabled',
    'anthropic_api_key',
    'ai_model',
    'ai_provider_openai_enabled',
    'openai_api_key',
    'openai_model'
);
