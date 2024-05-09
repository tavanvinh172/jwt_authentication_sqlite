const express = require("express");
const sqlite3 = require("sqlite3").verbose();
const jwt = require("jsonwebtoken");
const fs = require("fs");
const bcrypt = require("bcryptjs");
const xmlparser = require("express-xml-bodyparser");

// Initialize Express app
const app = express();
app.use(express.json());
app.use(xmlparser());
// Connect to SQLite database
const db = new sqlite3.Database("./mydb.sqlite3", (err) => {
  if (err) {
    console.error(err.message);
  }
  console.log("Connected to the SQLite database.");
});

var os = require("os");

var networkInterfaces = os.networkInterfaces();

var address = networkInterfaces.WiFi[0].address;

// Create users table if it doesn't exist
db.run(`CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  username TEXT UNIQUE,
  password TEXT
)`);

// Register new user
app.post("/register", (req, res) => {
  const { username, password } = req.body;
  const hashedPassword = bcrypt.hashSync(password, 8);
  db.run(
    "INSERT INTO users (username, password) VALUES (?, ?)",
    [username, hashedPassword],
    function (err) {
      if (err) {
        return res.status(500).send("User already exists");
      }
      // Create a token
      const token = jwt.sign({ id: this.lastID }, "supersecret", {
        expiresIn: 86400, // expires in 24 hours
      });
      res.status(200).send({ auth: true, token: token });
    }
  );
});

// Login user
app.post("/login", (req, res) => {
  const { username, password } = req.body;

  db.get("SELECT * FROM users WHERE username = ?", [username], (err, user) => {
    if (err) {
      return res.status(500).send("Error on the server.");
    }
    if (!user) {
      return res.status(404).send("No user found.");
    }
    const passwordIsValid = bcrypt.compareSync(password, user.password);
    if (!passwordIsValid) {
      return res.status(401).send({ auth: false, token: null });
    }
    const token = jwt.sign({ id: user.id }, "supersecret", {
      expiresIn: 86400, // expires in 24 hours
    });
    res.status(200).send({ auth: true, token: token });
  });
});

// Middleware to verify token
const verifyToken = (req, res, next) => {
  const token = req.headers["authorization"].split(" ")[1];
  if (!token) {
    return res.status(403).send({ auth: false, message: "No token provided." });
  }
  jwt.verify(token, "supersecret", (err, decoded) => {
    if (err) {
      return res
        .status(500)
        .send({ auth: false, message: "Failed to authenticate token." });
    }
    req.userId = decoded.id;
    next();
  });
};

// GET all users
app.get("/users", (req, res) => {
  db.all("SELECT id, username FROM users", [], (err, rows) => {
    if (err) {
      res.status(500).json({ error: err.message });
      return;
    }
    res.json({
      message: "Success",
      data: rows,
    });
  });
});

app.post("/getData", (req, res) => {
  if (req.body.type) {
    const rssFile = fs.readFileSync("./alarm.xml", { encoding: "utf8" });
    res.set("Content-Type", "text/xml");
    res.status(200).send({
      message: "Success",
      data: rssFile,
    });
  }
});

const server = require("http").createServer();

// Protected route
app.get("/protected", verifyToken, (req, res) => {
  res.status(200).send("Welcome to the protected route!");
});

const PORT = process.env.PORT || 3000;
const IP_ADDRESS = address; // Your IP address
app.listen(PORT, IP_ADDRESS, () => {
  console.log(`Server is running on http://${IP_ADDRESS}:${PORT}`);
});
