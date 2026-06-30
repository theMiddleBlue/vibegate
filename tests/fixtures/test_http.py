# Fixture: HTTP_BODY with email and password.
from flask import request


def register():
    email = request.json.get("email")
    password = request.json.get("password")
    user_id = request.json.get("id")
    return {"ok": True, "email": email, "password": password, "user_id": user_id}
