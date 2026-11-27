"""Test environment: set before any app module (and its settings) is imported."""
import os
import tempfile

os.environ["DATABASE_URL"] = f"sqlite+aiosqlite:///{tempfile.mkdtemp()}/test.db"
os.environ.update(LLM_PROVIDER="mock", INGEST_API_KEY="test-key", JWT_SECRET="test-secret-test-secret-test-secret",
                  ADMIN_PASSWORD="admin-pass", ANALYST_PASSWORD="analyst-pass")
