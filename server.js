const crypto = require("node:crypto");
const path = require("node:path");
const express = require("express");
const session = require("express-session");
const connectPgSimple = require("connect-pg-simple");
const bcrypt = require("bcryptjs");
const { rateLimit } = require("express-rate-limit");
const { Pool } = require("pg");

const app = express();
const port = Number(process.env.PORT) || 3000;
const isProduction = process.env.NODE_ENV === "production";
const sessionSecret = process.env.SESSION_SECRET;
const trackingSecret = process.env.TRACKING_SECRET;
const ownerPasswordHash = process.env.OWNER_PASSWORD_HASH;

if (!process.env.DATABASE_URL) throw new Error("DATABASE_URL is required.");
if (!sessionSecret || sessionSecret.length < 32) throw new Error("SESSION_SECRET must be at least 32 characters.");
if (!trackingSecret || trackingSecret.length < 32) throw new Error("TRACKING_SECRET must be at least 32 characters.");
if (!ownerPasswordHash || !/^\$2[aby]\$/.test(ownerPasswordHash)) throw new Error("OWNER_PASSWORD_HASH must be a bcrypt hash.");

app.disable("x-powered-by");
app.set("trust proxy", 1);
app.use(express.json({ limit: "2kb", type: "application/json" }));

const pool = new Pool({
    connectionString: process.env.DATABASE_URL,
    ssl: isProduction ? { rejectUnauthorized: false } : false,
    max: 10,
    idleTimeoutMillis: 30000,
    connectionTimeoutMillis: 10000
});

const PgSession = connectPgSimple(session);
app.use(session({
    store: new PgSession({ pool, tableName: "owner_sessions", createTableIfMissing: true }),
    name: "portfolio_owner_session",
    secret: sessionSecret,
    resave: false,
    saveUninitialized: false,
    cookie: {
        httpOnly: true,
        secure: isProduction,
        sameSite: "strict",
        maxAge: 8 * 60 * 60 * 1000
    }
}));

function requireSameOrigin(req, res, next) {
    const origin = req.get("origin");
    if (!origin) return res.status(403).json({ error: "Request origin is required." });
    try {
        const requestOrigin = new URL(origin);
        if (requestOrigin.host !== req.get("host") || requestOrigin.protocol !== `${req.protocol}:`) {
            return res.status(403).json({ error: "Cross-origin request denied." });
        }
    } catch {
        return res.status(403).json({ error: "Invalid request origin." });
    }
    next();
}

function cleanText(value, limit) {
    return typeof value === "string"
        ? value.replace(/[\u0000-\u001f\u007f]/g, "").trim().slice(0, limit)
        : "";
}

function parsePage(value) {
    const page = cleanText(value, 1000);
    if (!page.startsWith("/")) return "/";
    try {
        return new URL(page, "https://portfolio.invalid").pathname.slice(0, 500) || "/";
    } catch {
        return "/";
    }
}

function parseReferrer(value, requestHost) {
    const input = cleanText(value, 2000);
    if (!input) return null;
    try {
        const referrer = new URL(input);
        if (!/^https?:$/.test(referrer.protocol) || referrer.host === requestHost) return null;
        return referrer.hostname.toLowerCase().slice(0, 253);
    } catch {
        return null;
    }
}

function getBrowser(userAgent) {
    if (/Edg\//i.test(userAgent)) return "Edge";
    if (/OPR\//i.test(userAgent)) return "Opera";
    if (/Firefox\//i.test(userAgent)) return "Firefox";
    if (/CriOS|Chrome\//i.test(userAgent)) return "Chrome";
    if (/Safari\//i.test(userAgent) && !/Chrome|Chromium|Android/i.test(userAgent)) return "Safari";
    return "Other";
}

function getDevice(userAgent) {
    if (/iPad|Tablet|PlayBook|Silk/i.test(userAgent)) return "Tablet";
    if (/Mobi|iPhone|iPod|Android/i.test(userAgent)) return "Mobile";
    return "Desktop";
}

function getVisitorHash(req, res) {
    const cookieName = "portfolio_visitor";
    const cookieHeader = req.get("cookie") || "";
    const cookies = Object.fromEntries(cookieHeader.split(";").map((part) => {
        const separator = part.indexOf("=");
        return separator < 0 ? ["", ""] : [part.slice(0, separator).trim(), part.slice(separator + 1).trim()];
    }));
    let visitorId = cookies[cookieName] || "";
    if (!/^[0-9a-f-]{36}$/i.test(visitorId)) {
        visitorId = crypto.randomUUID();
        res.cookie(cookieName, visitorId, {
            httpOnly: true,
            secure: isProduction,
            sameSite: "lax",
            maxAge: 365 * 24 * 60 * 60 * 1000,
            path: "/"
        });
    }
    return crypto.createHmac("sha256", trackingSecret).update(visitorId).digest("hex");
}

function getSource(utmSource, referralHost) {
    const campaign = cleanText(utmSource, 100).replace(/[^\p{L}\p{N} _.-]/gu, "");
    return campaign || referralHost || "Direct";
}

app.get("/healthz", (_req, res) => res.status(200).json({ status: "ok" }));

app.post("/api/analytics/visit", requireSameOrigin, async (req, res, next) => {
    try {
        const userAgent = cleanText(req.get("user-agent"), 500);
        const referralHost = parseReferrer(req.body?.referrer, req.get("host"));
        const visitorHash = getVisitorHash(req, res);
        await pool.query(
            `INSERT INTO visitor_events
                (visitor_hash, page_path, source, referral_host, browser, device_type)
             VALUES ($1, $2, $3, $4, $5, $6)`,
            [visitorHash, parsePage(req.body?.page), getSource(req.body?.utmSource, referralHost),
                referralHost, getBrowser(userAgent), getDevice(userAgent)]
        );
        const result = await pool.query(
            "SELECT COUNT(DISTINCT visitor_hash)::text AS unique_visitors FROM visitor_events"
        );
        res.status(202).json({ uniqueVisitors: result.rows[0].unique_visitors });
    } catch (error) {
        next(error);
    }
});

const loginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    limit: 10,
    standardHeaders: true,
    legacyHeaders: false,
    message: { error: "Too many login attempts. Try again later." }
});

app.use("/api/admin", (_req, res, next) => {
    res.set("Cache-Control", "no-store");
    next();
});

app.post("/api/admin/login", requireSameOrigin, loginLimiter, async (req, res, next) => {
    try {
        const password = typeof req.body?.password === "string" ? req.body.password : "";
        if (password.length > 1024 || !(await bcrypt.compare(password, ownerPasswordHash))) {
            return res.status(401).json({ error: "Invalid password." });
        }
        req.session.regenerate((error) => {
            if (error) return next(error);
            req.session.isOwner = true;
            req.session.save((saveError) => {
                if (saveError) return next(saveError);
                res.json({ authenticated: true });
            });
        });
    } catch (error) {
        next(error);
    }
});

function requireOwner(req, res, next) {
    if (req.session.isOwner === true) return next();
    res.status(401).json({ error: "Authentication required." });
}

app.get("/api/admin/analytics", requireOwner, async (_req, res, next) => {
    try {
        const [totals, sources, pages, browsers, devices, referrals, daily, recent] = await Promise.all([
            pool.query(`SELECT COUNT(*)::int AS total_visits, COUNT(DISTINCT visitor_hash)::int AS unique_visitors FROM visitor_events`),
            pool.query(`SELECT source, COUNT(*)::int AS visits FROM visitor_events GROUP BY source ORDER BY visits DESC LIMIT 20`),
            pool.query(`SELECT page_path, COUNT(*)::int AS visits FROM visitor_events GROUP BY page_path ORDER BY visits DESC LIMIT 20`),
            pool.query(`SELECT browser, COUNT(*)::int AS visits FROM visitor_events GROUP BY browser ORDER BY visits DESC`),
            pool.query(`SELECT device_type, COUNT(*)::int AS visits FROM visitor_events GROUP BY device_type ORDER BY visits DESC`),
            pool.query(`SELECT referral_host, COUNT(*)::int AS visits FROM visitor_events WHERE referral_host IS NOT NULL GROUP BY referral_host ORDER BY visits DESC LIMIT 20`),
            pool.query(`SELECT to_char(date_trunc('day', visited_at)::date, 'YYYY-MM-DD') AS day,
                               COUNT(*)::int AS visits,
                               COUNT(DISTINCT visitor_hash)::int AS unique_visitors
                        FROM visitor_events WHERE visited_at >= now() - interval '30 days'
                        GROUP BY day ORDER BY day`),
            pool.query(`SELECT page_path, source, referral_host, browser, device_type, visited_at
                        FROM visitor_events ORDER BY visited_at DESC LIMIT 100`)
        ]);
        res.set("Cache-Control", "no-store");
        res.json({ totals: totals.rows[0], sources: sources.rows, pages: pages.rows,
            browsers: browsers.rows, devices: devices.rows, referrals: referrals.rows,
            daily: daily.rows, recent: recent.rows });
    } catch (error) {
        next(error);
    }
});

app.post("/api/admin/logout", requireSameOrigin, requireOwner, (req, res, next) => {
    req.session.destroy((error) => {
        if (error) return next(error);
        res.clearCookie("portfolio_owner_session", {
            httpOnly: true, secure: isProduction, sameSite: "strict", path: "/"
        });
        res.status(204).end();
    });
});

app.get("/admin", (_req, res) => res.sendFile(path.join(__dirname, "admin.html")));
app.get("/scripts/analytics.js", (_req, res) => res.sendFile(path.join(__dirname, "analytics.js")));
app.use("/images", express.static(path.join(__dirname, "images"), { maxAge: "1d", fallthrough: false }));
app.get("/", (_req, res) => res.sendFile(path.join(__dirname, "index.html")));
app.use((_req, res) => res.status(404).send("Not found"));
app.use((error, _req, res, _next) => {
    console.error("Request failed:", error.message);
    if (!res.headersSent) res.status(500).json({ error: "Request could not be completed." });
});

async function start() {
    await pool.query(`CREATE TABLE IF NOT EXISTS visitor_events (
        id BIGSERIAL PRIMARY KEY,
        visitor_hash CHAR(64) NOT NULL,
        page_path TEXT NOT NULL,
        source TEXT NOT NULL,
        referral_host TEXT,
        browser TEXT NOT NULL,
        device_type TEXT NOT NULL,
        visited_at TIMESTAMPTZ NOT NULL DEFAULT now()
    )`);
    await pool.query("CREATE INDEX IF NOT EXISTS visitor_events_visited_at_idx ON visitor_events (visited_at DESC)");
    await pool.query("CREATE INDEX IF NOT EXISTS visitor_events_source_idx ON visitor_events (source)");

    const server = app.listen(port, "0.0.0.0", () => console.log(`Portfolio server listening on port ${port}`));
    const shutdown = () => server.close(async () => {
        await pool.end();
        process.exit(0);
    });
    process.on("SIGTERM", shutdown);
    process.on("SIGINT", shutdown);
}

start().catch((error) => {
    console.error("Could not start portfolio server:", error.message);
    process.exit(1);
});