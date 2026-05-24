import os
import shutil
import asyncio
import gc
from pathlib import Path
import pytest

from backend.api.routes.auth import unlock, UnlockRequest, LockResponse
from fastapi import Request, HTTPException


def get_mock_request() -> Request:
    """Creates a real starlette.requests.Request instance with a mock HTTP scope

    so that slowapi rate-limiting decorator's isinstance check passes.
    """
    scope = {
        "type": "http",
        "method": "POST",
        "path": "/api/v1/auth/unlock",
        "headers": [],
        "client": ("127.0.0.1", 12345),
    }
    return Request(scope=scope)


@pytest.fixture(autouse=True)
def setup_and_teardown_db(monkeypatch):
    """Fixture to isolate each test run with a temporary database file."""
    # Create a temporary directory inside the tests folder
    temp_dir = Path(__file__).resolve().parent / "temp_db"
    temp_dir.mkdir(exist_ok=True)
    temp_db_path = str(temp_dir / "vault_test.db")
    temp_salt_path = str(Path(temp_db_path).with_suffix(".salt"))
    
    # Mock the get_db_path function used in the auth router to return this temp path
    monkeypatch.setattr("backend.api.routes.auth.get_db_path", lambda: temp_db_path)
    
    # Force garbage collection to release any files/handles
    gc.collect()

    # Remove any pre-existing database and salt files
    for path in (temp_db_path, temp_salt_path):
        if Path(path).exists():
            try:
                os.remove(path)
            except Exception:
                pass
            
    yield temp_db_path
    
    # Force garbage collection to release any files/handles before cleanup
    gc.collect()

    # Clean up the database file, salt file, and temp folder after the test run
    for path in (temp_db_path, temp_salt_path):
        if Path(path).exists():
            try:
                os.remove(path)
            except Exception:
                pass
    if temp_dir.exists():
        try:
            shutil.rmtree(temp_dir)
        except Exception:
            pass


@pytest.mark.anyio
async def test_first_unlock_success(setup_and_teardown_db):
    """On first unlock ever, any password should be accepted, hashing should occur,

    and a session token should be returned successfully.
    """
    temp_db = setup_and_teardown_db
    assert not Path(temp_db).exists()

    req = get_mock_request()
    body = UnlockRequest(password="first_time_password")
    
    response = await unlock(req, body)
    assert response.session_token is not None
    assert Path(temp_db).exists()


@pytest.mark.anyio
async def test_subsequent_unlock_correct_password(setup_and_teardown_db):
    """Subsequent unlocks with the same password must succeed."""
    req = get_mock_request()
    
    # First unlock to initialize
    response = await unlock(req, UnlockRequest(password="secret_password"))
    assert response.session_token is not None
    
    # Second unlock with the same correct password
    response2 = await unlock(req, UnlockRequest(password="secret_password"))
    assert response2.session_token is not None


@pytest.mark.anyio
async def test_subsequent_unlock_wrong_password(setup_and_teardown_db):
    """Subsequent unlocks with an incorrect password must raise HTTP 401."""
    req = get_mock_request()
    
    # First unlock to initialize
    response = await unlock(req, UnlockRequest(password="correct_password"))
    assert response.session_token is not None
    
    # Second unlock with a wrong password
    with pytest.raises(HTTPException) as exc_info:
        await unlock(req, UnlockRequest(password="wrong_password"))
        
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid password"


@pytest.mark.anyio
async def test_salt_exists_but_db_deleted(setup_and_teardown_db):
    """If .salt exists but the .db file does not, it must raise HTTP 401 'invalid password'."""
    temp_db = setup_and_teardown_db
    req = get_mock_request()
    
    # Create the salt file but do not create the db file
    temp_salt_path = str(Path(temp_db).with_suffix(".salt"))
    with open(temp_salt_path, "wb") as f:
        f.write(os.urandom(16))
        
    assert not Path(temp_db).exists()
    assert Path(temp_salt_path).exists()
    
    # Try to unlock — should raise HTTP 401
    with pytest.raises(HTTPException) as exc_info:
        await unlock(req, UnlockRequest(password="any_password"))
        
    assert exc_info.value.status_code == 401
    assert exc_info.value.detail == "invalid password"
