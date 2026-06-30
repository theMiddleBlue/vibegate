// Fixture: Express HTTP_BODY + EXEC_INPUT.
const { exec } = require("child_process");

function handler(req, res) {
  const email = req.body.email;
  const cmd = req.query.command;
  exec(cmd);
  res.json({ email });
}
