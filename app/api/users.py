"""
/api/users/* — user management (admin) + self-service password change.
"""
from __future__ import annotations

import aiosqlite
from fastapi import APIRouter, Depends, HTTPException, status
from pydantic import BaseModel

from app.database import get_db
from app.dependencies import CurrentUser, AdminUser
from app.auth.local import hash_password, verify_password

router = APIRouter()


class CreateUserRequest(BaseModel):
    username: str
    email: str
    password: str
    role: str = "viewer"


class UpdateUserRequest(BaseModel):
    username: str | None = None
    email: str | None = None
    password: str | None = None
    role: str | None = None
    is_active: bool | None = None


class ChangePasswordRequest(BaseModel):
    current_password: str
    new_password: str


class ResetPasswordRequest(BaseModel):
    new_password: str


def _user_out(row) -> dict:
    return {
        "id": row["id"],
        "username": row["username"],
        "email": row["email"],
        "role": row["role"],
        "is_active": bool(row["is_active"]),
        "is_default_admin": bool(row["is_default_admin"]) if "is_default_admin" in row.keys() else False,
        "auth_provider": row["auth_provider"],
        "created_at": row["created_at"],
        "last_login": row["last_login"],
        "has_password": bool(row["hashed_password"]) if "hashed_password" in row.keys() else True,
    }


@router.get("/me")
async def get_me(user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    if user.get("_via_suite"):
        return {
            "id": 0, "username": user["username"], "email": user["email"], "role": user["role"],
            "is_active": True, "auth_provider": "suite", "created_at": user["created_at"],
            "last_login": None, "has_password": False,
        }
    async with db.execute("SELECT * FROM users WHERE id = ?", (user["id"],)) as cur:
        row = await cur.fetchone()
    return _user_out(row)


@router.get("")
async def list_users(user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute(
        "SELECT id, username, email, role, is_active, is_default_admin, auth_provider, created_at, last_login "
        "FROM users ORDER BY username"
    ) as cur:
        rows = await cur.fetchall()
    return [_user_out(r) for r in rows]


@router.post("", status_code=201)
async def create_user(body: CreateUserRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    if body.role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")
    try:
        cur = await db.execute(
            "INSERT INTO users (username, email, hashed_password, role) VALUES (?, ?, ?, ?) RETURNING *",
            (body.username, body.email, hash_password(body.password), body.role),
        )
        row = await cur.fetchone()
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(status_code=409, detail="Username or email already exists")
    return _user_out(row)


@router.patch("/{user_id}")
async def update_user(user_id: int, body: UpdateUserRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    async with db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cur:
        existing = await cur.fetchone()
    if not existing:
        raise HTTPException(status_code=404, detail="User not found")

    username  = body.username if body.username is not None else existing["username"]
    email     = body.email if body.email is not None else existing["email"]
    role      = body.role if body.role is not None else existing["role"]
    is_active = int(body.is_active) if body.is_active is not None else existing["is_active"]
    if role not in ("admin", "analyst", "viewer"):
        raise HTTPException(status_code=400, detail="Invalid role")

    try:
        if body.password:
            await db.execute(
                "UPDATE users SET username = ?, email = ?, role = ?, is_active = ?, hashed_password = ? WHERE id = ?",
                (username, email, role, is_active, hash_password(body.password), user_id),
            )
        else:
            await db.execute(
                "UPDATE users SET username = ?, email = ?, role = ?, is_active = ? WHERE id = ?",
                (username, email, role, is_active, user_id),
            )
        await db.commit()
    except aiosqlite.IntegrityError:
        raise HTTPException(status_code=409, detail="Username or email already exists")
    async with db.execute("SELECT * FROM users WHERE id = ?", (user_id,)) as cur:
        row = await cur.fetchone()
    return _user_out(row)


@router.patch("/{user_id}/reset-password", status_code=204)
async def reset_user_password(user_id: int, body: ResetPasswordRequest, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    """Admin-only: set a user's password without knowing the current one."""
    if not body.new_password or len(body.new_password) < 6:
        raise HTTPException(status_code=400, detail="Password must be at least 6 characters")
    async with db.execute("SELECT id FROM users WHERE id = ?", (user_id,)) as cur:
        if not await cur.fetchone():
            raise HTTPException(status_code=404, detail="User not found")
    await db.execute("UPDATE users SET hashed_password = ? WHERE id = ?", (hash_password(body.new_password), user_id))
    await db.commit()


@router.patch("/{user_id}/set-default-admin", status_code=204)
async def set_default_admin(user_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    """Mark this user as the account auto-logged-in when every auth method is disabled.

    Exactly one user can hold the flag at a time — setting it here clears it from
    every other user in the same transaction (radio-button semantics, not a toggle).
    """
    async with db.execute("SELECT role, is_active FROM users WHERE id = ?", (user_id,)) as cur:
        row = await cur.fetchone()
    if not row:
        raise HTTPException(status_code=404, detail="User not found")
    if row["role"] != "admin" or not row["is_active"]:
        raise HTTPException(status_code=400, detail="Default admin must be an active admin account")
    await db.execute("UPDATE users SET is_default_admin = 0")
    await db.execute("UPDATE users SET is_default_admin = 1 WHERE id = ?", (user_id,))
    await db.commit()


@router.delete("/{user_id}", status_code=204)
async def delete_user(user_id: int, user: AdminUser, db: aiosqlite.Connection = Depends(get_db)):
    if user_id == user["id"]:
        raise HTTPException(status_code=400, detail="Cannot delete your own account")
    await db.execute("DELETE FROM users WHERE id = ?", (user_id,))
    await db.commit()


@router.post("/me/change-password")
async def change_my_password(body: ChangePasswordRequest, user: CurrentUser, db: aiosqlite.Connection = Depends(get_db)):
    if user.get("_via_suite"):
        raise HTTPException(status_code=400, detail="Password managed by pktHub for suite-authenticated sessions")
    async with db.execute("SELECT hashed_password FROM users WHERE id = ?", (user["id"],)) as cur:
        row = await cur.fetchone()
    if not row or not row["hashed_password"] or not verify_password(body.current_password, row["hashed_password"]):
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Current password is incorrect")
    await db.execute(
        "UPDATE users SET hashed_password = ? WHERE id = ?",
        (hash_password(body.new_password), user["id"]),
    )
    await db.commit()
    return {"status": "ok"}
