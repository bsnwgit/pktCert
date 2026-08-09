"""
SAML 2.0 SP helpers for pktCert.
Identical to the pktSNMP/pktFlow implementation — only the default base_url differs.
"""
from __future__ import annotations

import json as _json
from typing import Optional
from urllib.parse import urlparse

from fastapi import Request
from onelogin.saml2.auth import OneLogin_Saml2_Auth


def _decode(raw_kv: dict, key: str, default="") -> str:
    raw = raw_kv.get(key, _json.dumps(default))
    try:
        val = _json.loads(raw)
    except Exception:
        val = raw
    return str(val).strip() if val is not None else default


async def load_saml_settings(db) -> Optional[dict]:
    keys = (
        "okta_saml_enabled", "okta_saml_idp_entity_id", "okta_saml_idp_sso_url",
        "okta_saml_idp_cert", "okta_saml_sp_entity_id",
        "okta_saml_sp_cert", "okta_saml_sp_key", "base_url",
    )
    placeholders = ",".join(["?"] * len(keys))
    async with db.execute(
        f"SELECT key, value FROM settings WHERE key IN ({placeholders})", keys
    ) as cur:
        rows = await cur.fetchall()

    kv = {r["key"]: r["value"] for r in rows}

    try:
        enabled = _json.loads(kv.get("okta_saml_enabled", "false"))
    except Exception:
        enabled = False
    if isinstance(enabled, str):
        enabled = enabled.lower() in ("true", "1", "yes")
    if not enabled:
        return None

    idp_entity_id = _decode(kv, "okta_saml_idp_entity_id")
    idp_sso_url   = _decode(kv, "okta_saml_idp_sso_url")
    idp_cert      = _decode(kv, "okta_saml_idp_cert")

    if not all([idp_entity_id, idp_sso_url, idp_cert]):
        return None

    base_url     = _decode(kv, "base_url", "http://localhost:8763").rstrip("/")
    sp_entity_id = _decode(kv, "okta_saml_sp_entity_id") or f"{base_url}/api/auth/saml/metadata"
    acs_url      = f"{base_url}/api/auth/saml/callback"

    return {
        "base_url":      base_url,
        "sp_entity_id":  sp_entity_id,
        "acs_url":       acs_url,
        "idp_entity_id": idp_entity_id,
        "idp_sso_url":   idp_sso_url,
        "idp_cert":      idp_cert,
        "sp_cert":       _decode(kv, "okta_saml_sp_cert"),
        "sp_key":        _decode(kv, "okta_saml_sp_key"),
    }


def _build_saml_settings(cfg: dict) -> dict:
    sp: dict = {
        "entityId": cfg["sp_entity_id"],
        "assertionConsumerService": {
            "url": cfg["acs_url"],
            "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST",
        },
        "NameIDFormat": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    }
    if cfg.get("sp_cert") and cfg.get("sp_key"):
        sp["x509cert"] = cfg["sp_cert"]
        sp["privateKey"] = cfg["sp_key"]

    return {
        "strict": True,
        "debug": False,
        "sp": sp,
        "idp": {
            "entityId": cfg["idp_entity_id"],
            "singleSignOnService": {
                "url": cfg["idp_sso_url"],
                "binding": "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-Redirect",
            },
            "x509cert": cfg["idp_cert"],
        },
        "security": {
            "authnRequestsSigned":   bool(cfg.get("sp_cert")),
            "wantAssertionsSigned":  True,
            "wantMessagesSigned":    False,
            "wantNameId":            True,
            "wantAttributeStatement": False,
            "requestedAuthnContext": False,
            "signatureAlgorithm":    "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256",
            "digestAlgorithm":       "http://www.w3.org/2001/04/xmlenc#sha256",
        },
    }


async def _prepare_request(request: Request) -> dict:
    body = {}
    if request.method == "POST":
        form = await request.form()
        body = dict(form)
    parsed = urlparse(str(request.url))
    return {
        "https":       "on" if parsed.scheme == "https" else "off",
        "http_host":   request.headers.get("host", parsed.netloc),
        "server_port": str(parsed.port or (443 if parsed.scheme == "https" else 80)),
        "script_name": parsed.path,
        "get_data":    dict(request.query_params),
        "post_data":   body,
    }


async def get_auth(request: Request, cfg: dict) -> OneLogin_Saml2_Auth:
    saml_settings = _build_saml_settings(cfg)
    req = await _prepare_request(request)
    return OneLogin_Saml2_Auth(req, saml_settings)


def get_metadata_xml(cfg: dict) -> str:
    saml_settings = _build_saml_settings(cfg)
    from onelogin.saml2.settings import OneLogin_Saml2_Settings
    settings_obj = OneLogin_Saml2_Settings(settings=saml_settings, sp_validation_only=True)
    metadata = settings_obj.get_sp_metadata()
    errors = settings_obj.validate_metadata(metadata)
    if errors:
        raise ValueError(f"SP metadata validation errors: {errors}")
    return metadata
