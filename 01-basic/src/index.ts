import express from "express";
import bcrypt from "bcrypt";
import { pool, initDb } from "./db";
import { basicAuth } from "./middleware/basicAuth";

const app = express();
app.use(express.json());

// 회원가입
app.post("/register", async (req, res) => {
  const { username, password } = req.body;

  if (!username || !password) {
    res.status(400).json({ error: "username and password are required" });
    return;
  }

  const passwordHash = await bcrypt.hash(password, 10);

  try {
    const result = await pool.query(
      "INSERT INTO users (username, password_hash) VALUES ($1, $2) RETURNING id, username",
      [username, passwordHash]
    );
    res.status(201).json({ user: result.rows[0] });
  } catch (err: any) {
    if (err.code === "23505") {
      res.status(409).json({ error: "Username already exists" });
      return;
    }
    throw err;
  }
});

// Basic Auth가 필요한 보호된 라우트
app.get("/protected", basicAuth, (req, res) => {
  res.json({
    message: "Access granted",
    user: res.locals.user,
  });
});

const PORT = process.env.PORT || 3000;

initDb().then(() => {
  app.listen(PORT, () => {
    console.log(`Server running on port ${PORT}`);
  });
});
