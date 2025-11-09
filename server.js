const express = require("express");
const bodyParser = require("body-parser");
const session = require("express-session");
const SQLiteStore = require("connect-sqlite3")(session);
const sqlite3 = require("sqlite3").verbose();
const bcrypt = require("bcrypt");

const db = new sqlite3.Database("./db.sqlite3");

const expressLayouts = require("express-ejs-layouts");
const path = require("path");
const app = express();

app.set("views", path.join(__dirname, "views"));
app.set("view engine", "ejs");
app.use(expressLayouts);
app.set("layout", "layout");

app.use(bodyParser.urlencoded({ extended: true }));

app.use(
	session({
		store: new SQLiteStore({ db: "sessions.sqlite3" }),
		secret: "verysecretfortestonly",
		resave: false,
		saveUninitialized: false,
		cookie: { httpOnly: false },
	})
);

const vulnConfig = {
	xssEnabled: true,
	brokenAccessControlEnabled: true,
	insecureDirectObjectRefsEnabled: true,
	roleBasedUrlAccessEnabled: true,
};

db.serialize(() => {
	db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE,
    password TEXT,
    role TEXT
  )`);

	db.run(`CREATE TABLE IF NOT EXISTS accounts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    owner TEXT,
    balance REAL,
    type TEXT,
    FOREIGN KEY(owner) REFERENCES users(username)
  )`);

	db.run(`CREATE TABLE IF NOT EXISTS payments (
    id INTEGER PRIMARY KEY,
    owner TEXT,
    amount REAL,
    date TEXT,
    type TEXT,
    FOREIGN KEY(owner) REFERENCES users(username)
  )`);

	const seed = async () => {
		const hashAdmin = await bcrypt.hash("louvre", 10);
		const hashUser = await bcrypt.hash("usersifra", 10);

		db.run(
			`INSERT OR IGNORE INTO users (username,password,role) VALUES ('admin', ?, 'admin')`,
			[hashAdmin]
		);
		db.run(
			`INSERT OR IGNORE INTO users (username,password,role) VALUES ('user', ?, 'user')`,
			[hashUser]
		);

		db.run(
			`INSERT OR IGNORE INTO accounts (id, owner, balance, type) VALUES (1, 'user', 1000, 'user')`
		);
		db.run(
			`INSERT OR IGNORE INTO accounts (id, owner, balance, type) VALUES (2, 'admin', 50000, 'admin')`
		);

		db.run(
			`INSERT OR IGNORE INTO payments (id, owner, amount, date, type) VALUES (11, 'user', 250, '2024-11-01', 'utility')`
		);
		db.run(
			`INSERT OR IGNORE INTO payments (id, owner, amount, date, type) VALUES (12, 'user', 125, '2024-11-02', 'utility')`
		);
		db.run(
			`INSERT OR IGNORE INTO payments (id, owner, amount, date, type) VALUES (13, 'user', 89, '2024-11-03', 'shopping')`
		);

		db.run(
			`INSERT OR IGNORE INTO payments (id, owner, amount, date, type) VALUES (14, 'admin', 5000, '2024-11-01', 'business')`
		);
		db.run(
			`INSERT OR IGNORE INTO payments (id, owner, amount, date, type) VALUES (15, 'admin', 15000, '2024-11-02', 'business')`
		);
		db.run(
			`INSERT OR IGNORE INTO payments (id, owner, amount, date, type) VALUES (16, 'admin', 2500, '2024-11-03', 'business')`
		);
	};
	seed();
});

function requireLogin(req, res, next) {
	if (!req.session.username) return res.redirect("/login");
	next();
}

app.get("/", (req, res) => {
	res.render("index", { user: req.session.username, role: req.session.role });
});

app.get("/settings", (req, res) => {
	res.render("settings", {
		config: vulnConfig,
		user: req.session.username,
		role: req.session.role,
	});
});

app.post("/settings", (req, res) => {
	vulnConfig.xssEnabled = !!req.body.xss;
	vulnConfig.brokenAccessControlEnabled = !!req.body.bac;
	vulnConfig.insecureDirectObjectRefsEnabled = !!req.body.idor;
	vulnConfig.roleBasedUrlAccessEnabled = !!req.body.rbua;
	res.redirect("/settings");
});

app.get("/login", (req, res) =>
	res.render("login", {
		err: null,
		user: req.session.username,
		role: req.session.role,
	})
);
app.post("/login", (req, res) => {
	const { username, password } = req.body;
	db.get(
		`SELECT * FROM users WHERE username = ?`,
		[username],
		async (err, row) => {
			if (err || !row)
				return res.render("login", {
					err: "Bad creds",
					user: req.session.username,
					role: req.session.role,
				});
			const ok = await bcrypt.compare(password, row.password);
			if (!ok)
				return res.render("login", {
					err: "Bad creds",
					user: req.session.username,
					role: req.session.role,
				});
			req.session.username = row.username;
			req.session.role = row.role;
			res.redirect("/");
		}
	);
});

app.get("/logout", (req, res) => {
	req.session.destroy(() => res.redirect("/"));
});

// XSS DEMO
app.get("/search", requireLogin, (req, res) => {
	const q = req.query.q || "";
	res.render("xss-search", {
		user: req.session.username,
		role: req.session.role,
		q,
		xssEnabled: vulnConfig.xssEnabled,
	});
});

app.get("/accounts", requireLogin, (req, res) => {
	const userRole = req.session.role || "user";
	res.redirect(`/accounts/${userRole}`);
});

// BAC DEMO 1
app.get("/accounts/:role?", requireLogin, (req, res) => {
	let effectiveRole;

	if (vulnConfig.roleBasedUrlAccessEnabled) {
		effectiveRole = req.params.role || req.session.role;
	} else {
		effectiveRole = req.session.role;
	}

	let query = "";
	let params = [];

	if (effectiveRole === "admin") {
		query = "SELECT * FROM accounts";
	} else {
		query = "SELECT * FROM accounts WHERE owner = ?";
		params = [req.session.username];
	}

	db.all(query, params, (err, accounts) => {
		if (err) {
			console.error(err);
			return res.status(500).send("Database error");
		}

		res.render("accounts", {
			user: req.session.username,
			role: req.session.role,
			effectiveRole,
			accounts,
			config: vulnConfig,
		});
	});
});

// BAC DEMO 2
app.get("/account-payments", requireLogin, (req, res) => {
	const paymentId = req.query.id;

	const listQuery = "SELECT * FROM payments WHERE owner = ? ORDER BY id ASC";

	db.all(listQuery, [req.session.username], (err, availablePayments) => {
		if (err) {
			console.error(err);
			return res.status(500).send("Database error");
		}

		if (paymentId) {
			db.get(
				"SELECT * FROM payments WHERE id = ?",
				[paymentId],
				(err, payment) => {
					if (err) {
						console.error(err);
						return res.status(500).send("Database error");
					}

					if (!payment) {
						return res.status(404).send("Payment not found");
					}

					if (!vulnConfig.insecureDirectObjectRefsEnabled) {
						if (payment.owner !== req.session.username) {
							return res
								.status(403)
								.send(
									"Forbidden: You can only access your own payments"
								);
						}
					}
					res.render("account-payments", {
						user: req.session.username,
						role: req.session.role,
						payment: payment,
						availablePayments,
						config: vulnConfig,
					});
				}
			);
		} else {
			res.render("account-payments", {
				user: req.session.username,
				role: req.session.role,
				payment: null,
				availablePayments,
				config: vulnConfig,
			});
		}
	});
});

// BAC DEMO 3
app.get("/system-config", (req, res) => {
	if (!vulnConfig.brokenAccessControlEnabled) {
		if (req.session.role !== "admin") {
			return res.status(403).send("Forbidden: Admin access required");
		}
	}

	res.render("system-config", {
		user: req.session.username,
		role: req.session.role,
		config: vulnConfig,
		systemConfig: {
			dbConnection: "sqlite://./db.sqlite3",
			secretKey: "verysecretfortestonly",
			adminEmail: "admin@vulnerable-app.com",
		},
	});
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`server started`));
