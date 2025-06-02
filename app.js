import express from "express";
import bodyParser from "body-parser";
import pg from "pg";
import bcrypt from "bcrypt";
import session from "express-session";
import passport from "passport";
import { Strategy as LocalStrategy } from "passport-local";
import env from "dotenv";

env.config();

const app = express();
const port = 3000;
const saltRounds = 10;

// View engine
app.set("view engine", "ejs");
app.use(express.static("public"));
app.use(bodyParser.urlencoded({ extended: true }));

// Session setup
app.use(session({
  secret: process.env.SESSION_SECRET || "secret",
  resave: false,
  saveUninitialized: false
}));

app.use(passport.initialize());
app.use(passport.session());

// PostgreSQL connection
const db = new pg.Client({
  user: process.env.PG_USER || "postgres",
  host: process.env.PG_HOST || "localhost",
  database: process.env.PG_DATABASE || "auth_demo",
  password: process.env.PG_PASSWORD || "postgres",
  port: process.env.PG_PORT || 5432,
});
db.connect();

// Passport local strategy
passport.use(new LocalStrategy(
  { usernameField: "email" }, // important!
  async (email, password, done) => {
    try {
      const result = await db.query("SELECT * FROM users WHERE email = $1", [email]);
      if (result.rows.length === 0) {
        console.log("User not found");
        return done(null, false, { message: "User not found" });
      }

      const user = result.rows[0];
      const valid = await bcrypt.compare(password, user.password);
      if (valid) {
        console.log("Login successful");
        return done(null, user);
      } else {
        console.log("Invalid password");
        return done(null, false, { message: "Invalid password" });
      }
    } catch (err) {
      console.error("Login error:", err);
      return done(err);
    }
  }
));

passport.serializeUser((user, done) => {
  done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const result = await db.query("SELECT * FROM users WHERE id = $1", [id]);
    done(null, result.rows[0]);
  } catch (err) {
    done(err);
  }
});

// Middleware to protect routes
function ensureAuthenticated(req, res, next) {
  if (req.isAuthenticated()) return next();
  res.redirect("/login");
}

// Routes
app.get("/", (req, res) => res.redirect("/login"));

app.get("/register", (req, res) => {
  res.render("register");
});

app.post("/register", async (req, res) => {
  const { email, password } = req.body;
  try {
    const hashedPassword = await bcrypt.hash(password, saltRounds);
    await db.query("INSERT INTO users (email, password) VALUES ($1, $2)", [email, hashedPassword]);
    res.redirect("/login");
  } catch (err) {
    console.error("Registration error:", err);
    res.send("Error registering user.");
  }
});

app.get("/login", (req, res) => {
  res.render("login");
});

app.post("/login", (req, res, next) => {
  passport.authenticate("local", (err, user, info) => {
    if (err) return next(err);
    if (!user) {
      console.log("Login failed:", info.message);
      return res.redirect("/login");
    }
    req.logIn(user, (err) => {
      if (err) return next(err);
      return res.redirect("/dashboard");
    });
  })(req, res, next);
});

app.get("/dashboard", ensureAuthenticated, async (req, res) => {
  try {
    const result = await db.query(
      "SELECT content, created_at FROM secrets WHERE user_id = $1 ORDER BY created_at DESC",
      [req.user.id]
    );
    res.render("dashboard", {
      user: req.user.email,
      secrets: result.rows,
    });
  } catch (err) {
    console.error("Fetching secrets failed:", err);
    res.send("Error loading dashboard.");
  }
});


app.post("/secret", ensureAuthenticated, async (req, res) => {
  const { secret } = req.body;
  try {
    await db.query(
      "INSERT INTO secrets (user_id, content) VALUES ($1, $2)",
      [req.user.id, secret]
    );
    res.redirect("/dashboard");
  } catch (err) {
    console.error("Saving secret failed:", err);
    res.send("Error saving secret.");
  }
});



app.get("/logout", (req, res, next) => {
  req.logout((err) => {
    if (err) return next(err);
    res.redirect("/login");
  });
});

// Start server
app.listen(port, () => {
  console.log(`✅ Server running at http://localhost:${port}`);
});
