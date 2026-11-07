require("dotenv").config();

const express = require("express");
const http = require("http");
const path = require("path");
const fs = require("fs");
const crypto = require("crypto");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const { Pool } = require("pg");
const { Server } = require("socket.io");

const PORT = Number(process.env.PORT || 10000);
const JWT_SECRET = process.env.JWT_SECRET;

if (!JWT_SECRET || JWT_SECRET.length < 32) {
  throw new Error("JWT_SECRET 必須設定為至少 32 字元的隨機密鑰");
}
if (!process.env.DATABASE_URL) {
  throw new Error("缺少 DATABASE_URL");
}

const pool = new Pool({
  connectionString: process.env.DATABASE_URL,
  ssl: process.env.NODE_ENV === "production"
    ? { rejectUnauthorized: false }
    : false,
  max: 10
});

const app = express();
const server = http.createServer(app);

const io = new Server(server, {
  cors: { origin: true },
  transports: ["websocket", "polling"],
  pingInterval: 25000,
  pingTimeout: 20000
});

app.use(helmet({
  contentSecurityPolicy: false
}));
app.use(express.json({ limit: "20kb" }));
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 20,
  standardHeaders: true,
  legacyHeaders: false
});

function makeToken(user) {
  return jwt.sign(
    { sub: String(user.id), username: user.username },
    JWT_SECRET,
    { expiresIn: "7d" }
  );
}

function authenticate(req, res, next) {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ")
    ? header.slice(7)
    : "";

  try {
    req.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: "登入已失效，請重新登入" });
  }
}

function publicUser(user) {
  return {
    id: user.id,
    username: user.username,
    level: user.level,
    xp: user.xp,
    coins: user.coins,
    rating: user.rating,
    wins: user.wins,
    losses: user.losses,
    tags: user.tags
  };
}

// 自動建立資料表
async function initializeDatabase() {
  const sql = fs.readFileSync(
    path.join(__dirname, "schema.sql"),
    "utf8"
  );
  await pool.query(sql);
}

// -----------------------------
// ACCOUNT REGISTER
// -----------------------------
app.post("/api/register", authLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    if (!/^[a-zA-Z0-9_\u4e00-\u9fff]{3,20}$/.test(username)) {
      return res.status(400).json({
        error: "名稱需為 3 至 20 個英數字、底線或中文字"
      });
    }

    if (password.length < 10 || password.length > 72) {
      return res.status(400).json({
        error: "密碼長度需為 10 至 72 個字元"
      });
    }

    const hash = await bcrypt.hash(password, 12);

    const result = await pool.query(
      `INSERT INTO users(username, password_hash)
       VALUES($1, $2)
       RETURNING id, username, level, xp, coins, rating, wins, losses, tags`,
      [username, hash]
    );

    const user = result.rows[0];

    res.status(201).json({
      token: makeToken(user),
      user: publicUser(user)
    });
  } catch (error) {
    if (error.code === "23505") {
      return res.status(409).json({ error: "這個名稱已經有人使用" });
    }

    console.error("register:", error);
    res.status(500).json({ error: "註冊失敗" });
  }
});

// -----------------------------
// ACCOUNT LOGIN
// -----------------------------
app.post("/api/login", authLimiter, async (req, res) => {
  try {
    const username = String(req.body.username || "").trim();
    const password = String(req.body.password || "");

    const result = await pool.query(
      `SELECT * FROM users WHERE username = $1`,
      [username]
    );

    const user = result.rows[0];

    if (!user || !(await bcrypt.compare(password, user.password_hash))) {
      return res.status(401).json({
        error: "帳號或密碼錯誤"
      });
    }

    res.json({
      token: makeToken(user),
      user: publicUser(user)
    });
  } catch (error) {
    console.error("login:", error);
    res.status(500).json({ error: "登入失敗" });
  }
});

// -----------------------------
// CURRENT PLAYER
// -----------------------------
app.get("/api/me", authenticate, async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT id, username, level, xp, coins,
              rating, wins, losses, tags
       FROM users WHERE id = $1`,
      [req.user.sub]
    );

    if (!result.rows[0]) {
      return res.status(404).json({ error: "找不到玩家" });
    }

    res.json({ user: publicUser(result.rows[0]) });
  } catch (error) {
    console.error("me:", error);
    res.status(500).json({ error: "讀取玩家資料失敗" });
  }
});

// -----------------------------
// GLOBAL LEADERBOARD
// -----------------------------
app.get("/api/leaderboard", async (req, res) => {
  try {
    const result = await pool.query(
      `SELECT username, level, rating, wins, losses, tags
       FROM users
       ORDER BY rating DESC, wins DESC, tags DESC
       LIMIT 50`
    );

    res.json({ leaderboard: result.rows });
  } catch (error) {
    console.error("leaderboard:", error);
    res.status(500).json({ error: "排行榜讀取失敗" });
  }
});

app.get("/api/health", (req, res) => {
  res.json({ status: "online", service: "FLAG WAR INFINITY" });
});

// -----------------------------
// SOCKET AUTHENTICATION
// -----------------------------
io.use((socket, next) => {
  try {
    const token = socket.handshake.auth?.token;
    if (!token) return next(new Error("請先登入"));

    socket.user = jwt.verify(token, JWT_SECRET);
    next();
  } catch {
    next(new Error("登入憑證無效"));
  }
});

// -----------------------------
// MATCH ROOM MANAGEMENT
// -----------------------------
const rooms = new Map();
const MAX_PLAYERS = 8;
const MATCH_SECONDS = 180;
const WIN_SCORE = 10;

function newRoom() {
  const id = crypto.randomBytes(5).toString("hex").toUpperCase();

  const room = {
    id,
    players: new Map(),
    blue: 0,
    red: 0,
    started: false,
    finished: false,
    createdAt: Date.now(),
    timer: null
  };

  rooms.set(id, room);
  return room;
}

function roomState(room) {
  return {
    room: room.id,
    blue: room.blue,
    red: room.red,
    started: room.started,
    players: [...room.players.values()].map(p => ({
      id: p.id,
      username: p.username,
      team: p.team,
      x: p.x,
      z: p.z,
      yaw: p.yaw,
      tags: p.tags
    }))
  };
}

function broadcastRoom(room) {
  io.to(room.id).emit("room:state", roomState(room));
}

function findRoom() {
  for (const room of rooms.values()) {
    if (!room.started && !room.finished &&
        room.players.size < MAX_PLAYERS) {
      return room;
    }
  }
  return newRoom();
}

function startMatch(room) {
  if (room.started || room.players.size < 2) return;

  room.started = true;
  room.startedAt = Date.now();
  room.remaining = MATCH_SECONDS;

  io.to(room.id).emit("match:started", {
    room: room.id,
    seconds: MATCH_SECONDS
  });

  room.timer = setInterval(() => {
    if (room.finished) return;

    room.remaining--;

    io.to(room.id).emit("match:clock", {
      seconds: room.remaining,
      blue: room.blue,
      red: room.red
    });

    if (
      room.remaining <= 0 ||
      room.blue >= WIN_SCORE ||
      room.red >= WIN_SCORE
    ) {
      finishMatch(room);
    }
  }, 1000);
}

// -----------------------------
// FINISH AND SAVE MATCH
// -----------------------------
async function finishMatch(room) {
  if (room.finished) return;
  room.finished = true;

  if (room.timer) clearInterval(room.timer);

  const winner = room.blue === room.red
    ? "draw"
    : room.blue > room.red ? "blue" : "red";

  const duration = Math.max(
    0,
    Math.floor((Date.now() - room.startedAt) / 1000)
  );

  const client = await pool.connect();

  try {
    await client.query("BEGIN");

    const matchResult = await client.query(
      `INSERT INTO matches(
        room_code, blue_score, red_score, winner, duration_seconds
       )
       VALUES($1, $2, $3, $4, $5)
       RETURNING id`,
      [room.id, room.blue, room.red, winner, duration]
    );

    const matchId = matchResult.rows[0].id;

    for (const p of room.players.values()) {
      const result = winner === "draw"
        ? "draw"
        : winner === p.team ? "win" : "loss";

      const ratingChange = result === "win" ? 25
        : result === "loss" ? -10 : 5;

      await client.query(
        `INSERT INTO match_players(match_id, user_id, team, tags, result)
         VALUES($1, $2, $3, $4, $5)`,
        [matchId, p.id, p.team, p.tags, result]
      );

      await client.query(
        `UPDATE users SET
          wins = wins + $1,
          losses = losses + $2,
          tags = tags + $3,
          rating = GREATEST(0, rating + $4),
          xp = xp + $5,
          coins = coins + $6,
          level = 1 + FLOOR((xp + $5) / 150)::INTEGER
         WHERE id = $7`,
        [
          result === "win" ? 1 : 0,
          result === "loss" ? 1 : 0,
          p.tags,
          ratingChange,
          result === "win" ? 120 : 60,
          result === "win" ? 180 : 70,
          p.id
        ]
      );
    }

    await client.query("COMMIT");
  } catch (error) {
    await client.query("ROLLBACK");
    console.error("save match:", error);
  } finally {
    client.release();
  }

  io.to(room.id).emit("match:ended", {
    winner,
    blue: room.blue,
    red: room.red
  });

  setTimeout(() => {
    for (const socketId of room.players.keys()) {
      const s = io.sockets.sockets.get(socketId);
      if (s) s.leave(room.id);
    }
    rooms.delete(room.id);
  }, 15000);
}

// -----------------------------
// SOCKET EVENTS
// -----------------------------
io.on("connection", async socket => {
  const userId = Number(socket.user.sub);

  try {
    const result = await pool.query(
      `SELECT id, username FROM users WHERE id = $1`,
      [userId]
    );

    if (!result.rows[0]) {
      socket.disconnect(true);
      return;
    }

    socket.playerData = result.rows[0];
  } catch {
    socket.disconnect(true);
    return;
  }

  socket.on("match:join", () => {
    if (socket.roomId) return;

    const room = findRoom();
    const team = [...room.players.values()]
      .filter(p => p.team === "blue").length <=
      [...room.players.values()].filter(p => p.team === "red").length
      ? "blue" : "red";

    const player = {
      id: userId,
      username: socket.playerData.username,
      team,
      x: team === "blue" ? -12 : 12,
      z: 0,
      yaw: team === "blue" ? 0 : Math.PI,
      tags: 0,
      lastTag: 0,
      lastMove: 0
    };

    room.players.set(socket.id, player);
    socket.roomId = room.id;
    socket.join(room.id);

    socket.emit("match:joined", {
      room: room.id,
      team,
      playerId: userId,
      state: roomState(room)
    });

    broadcastRoom(room);
    startMatch(room);
  });

  // Server validates and clamps player position.
  socket.on("player:move", data => {
    const room = rooms.get(socket.roomId);
    if (!room || !room.started || room.finished) return;

    const p = room.players.get(socket.id);
    if (!p) return;

    const now = Date.now();
    if (now - p.lastMove < 45) return;
    p.lastMove = now;

    const x = Number(data?.x);
    const z = Number(data?.z);
    const yaw = Number(data?.yaw);

    if (![x, z, yaw].every(Number.isFinite)) return;

    p.x = Math.max(-45, Math.min(45, x));
    p.z = Math.max(-45, Math.min(45, z));
    p.yaw = Math.max(-Math.PI * 4, Math.min(Math.PI * 4, yaw));

    socket.to(room.id).emit("player:moved", {
      id: p.id,
      x: p.x,
      z: p.z,
      yaw: p.yaw
    });
  });

  // A fictional energy-tag action.
  // Server chooses the nearest valid opponent; client cannot choose a victim.
  socket.on("player:tag", () => {
    const room = rooms.get(socket.roomId);
    if (!room || !room.started || room.finished) return;

    const attacker = room.players.get(socket.id);
    if (!attacker) return;

    const now = Date.now();
    if (now - attacker.lastTag < 800) return;
    attacker.lastTag = now;

    let target = null;
    let bestDistance = 5;

    for (const other of room.players.values()) {
      if (other.id === attacker.id || other.team === attacker.team) continue;

      const distance = Math.hypot(
        attacker.x - other.x,
        attacker.z - other.z
      );

      if (distance < bestDistance) {
        bestDistance = distance;
        target = other;
      }
    }

    if (!target) {
      socket.emit("tag:miss");
      return;
    }

    attacker.tags++;

    if (attacker.team === "blue") room.blue++;
    else room.red++;

    io.to(room.id).emit("tag:scored", {
      attacker: attacker.username,
      target: target.username,
      team: attacker.team,
      blue: room.blue,
      red: room.red
    });

    if (room.blue >= WIN_SCORE || room.red >= WIN_SCORE) {
      finishMatch(room);
    }
  });

  socket.on("match:leave", () => {
    removePlayer(socket);
  });

  socket.on("disconnect", () => {
    removePlayer(socket);
  });
});

function removePlayer(socket) {
  const room = rooms.get(socket.roomId);
  if (!room) return;

  room.players.delete(socket.id);
  socket.roomId = null;

  broadcastRoom(room);

  if (room.players.size === 0) {
    if (room.timer) clearInterval(room.timer);
    rooms.delete(room.id);
  }
}

// -----------------------------
// START SERVER
// -----------------------------
async function main() {
  await initializeDatabase();

  server.listen(PORT, "0.0.0.0", () => {
    console.log(`FLAG WAR server listening on ${PORT}`);
  });
}

main().catch(error => {
  console.error("Server startup failed:", error);
  process.exit(1);
});
