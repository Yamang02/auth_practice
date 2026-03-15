import { Request, Response, NextFunction } from "express";
import bcrypt from "bcrypt";
import { pool } from "../db";

export async function basicAuth(
  req: Request,
  res: Response,
  next: NextFunction
) {
  const authHeader = req.headers.authorization;

  if (!authHeader || !authHeader.startsWith("Basic ")) {
    res.setHeader("WWW-Authenticate", 'Basic realm="Protected"');
    res.status(401).json({ error: "Authorization header missing" });
    return;
  }

  // "Basic <base64(username:password)>" 디코딩
  const base64 = authHeader.slice(6);
  const decoded = Buffer.from(base64, "base64").toString("utf-8");
  const colonIndex = decoded.indexOf(":");
  if (colonIndex === -1) {
    res.status(400).json({ error: "Invalid Authorization format" });
    return;
  }

  const username = decoded.slice(0, colonIndex);
  const password = decoded.slice(colonIndex + 1);

  const result = await pool.query(
    "SELECT * FROM users WHERE username = $1",
    [username]
  );
  const user = result.rows[0];

  if (!user) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  const isValid = await bcrypt.compare(password, user.password_hash);
  if (!isValid) {
    res.status(401).json({ error: "Invalid credentials" });
    return;
  }

  // 이후 핸들러에서 유저 정보 사용 가능
  res.locals.user = { id: user.id, username: user.username };
  next();
}
