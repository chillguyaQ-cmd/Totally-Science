import express from "express";
import session from "express-session";
import bcrypt from "bcrypt";
import http from "http";
import { createBareServer } from "@titaniumnetwork-dev/ultraviolet";

const app = express();
const server = http.createServer(app);
const bare = createBareServer("/bare/");

// CONFIG
const PASSWORD_HASH = await bcrypt.hash("changeme123", 10);

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(session({
  secret: "supersecretkey",
  resave: false,
  saveUninitialized: false
}));

// Auth middleware
function requireAuth(req, res, next) {
  if (req.session.authed) return next();
  res.redirect("/login");
}

// Static
app.use(express.static("public"));

// Login
app.get("/login", (_, res) => {
  res.sendFile(process.cwd() + "/public/login.html");
});

app.post("/login", async (req, res) => {
  const ok = await bcrypt.compare(req.body.password, PASSWORD_HASH);
  if (!ok) return res.send("Invalid password");

  req.session.authed = true;
  res.redirect("/");
});

// Protect proxy
app.use("/uv/", requireAuth, (req, res) => {
  bare.routeRequest(req, res);
});

server.on("upgrade", (req, socket, head) => {
  if (req.url.startsWith("/uv/")) {
    bare.routeUpgrade(req, socket, head);
  }
});

server.listen(8080, () =>
  console.log("Secure proxy on http://localhost:8080")
);
