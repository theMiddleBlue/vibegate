# Fixture: critical DB_QUERY + EXEC_INPUT from unsanitized input.
from flask import request


def login():
    pwd = request.json.get("password")
    cmd = request.args.get("command")
    cursor.execute("SELECT * FROM users WHERE pwd=" + pwd)  # noqa: F821
    os.system(cmd)  # noqa: F821
