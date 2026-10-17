import "dotenv/config";
import express from "express";
import cors from "cors";
import helmet from "helmet";
import rateLimit from "express-rate-limit";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";
import { User, Entry, Branch, ROLES, PAYMENT_METHODS, tokenKeyOf, amountOf } from "./models.js";

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET;
const MIN_QUANTITY = 0.0001;
const EPS = 1e-9;
const MANAGERS = ["admin", "purchase_admin"];
const ROLE_LABEL = { admin: "Admin", purchase_admin: "Purchase admin", sales_executive: "Sales executive" };
const allowedOrigins = (process.env.FRONTEND_ORIGIN || "http://localhost:5173")
  .split(",").map(x => x.trim().replace(/\/$/, "")).filter(Boolean);

if (!process.env.MONGODB_URI || !JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Configuration error: set MONGODB_URI and JWT_SECRET (32+ characters) in server/.env.");
  process.exit(1);
}
if (/replace_with/i.test(JWT_SECRET)) {
  console.error("Configuration error: JWT_SECRET is still the placeholder. Generate a random secret.");
  process.exit(1);
}

// Needed for correct client IPs (rate limiting) behind Render/Railway/Heroku-style proxies.
app.set("trust proxy", 1);
app.use(helmet());
app.use(cors({
  origin(origin, callback) {
    if (!origin || allowedOrigins.includes(origin.replace(/\/$/, ""))) return callback(null, true);
    return callback(new Error(`CORS blocked origin: ${origin}`));
  }
}));
app.use(express.json({ limit: "1mb" }));

const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 10,
  skipSuccessfulRequests: true,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many sign-in attempts. Try again in 15 minutes." }
});
app.use("/api", rateLimit({
  windowMs: 60 * 1000,
  limit: 300,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { message: "Too many requests. Slow down and try again." }
}));

// ---------- helpers ----------
const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const round = (n, dp = 4) => Math.round((Number(n) || 0) * 10 ** dp) / 10 ** dp;
const publicBranch = b => (b && b.name !== undefined ? { id: b._id, name: b.name, location: b.location, active: b.active } : null);
const publicUser = u => ({ id: u._id, name: u.name, email: u.email, role: u.role, active: u.active, branch: publicBranch(u.branch) });
const isManager = user => MANAGERS.includes(user.role);

// Admin manages everyone; purchase admin manages only sales executives.
const canManageRole = (actor, role) => actor.role === "admin" || (actor.role === "purchase_admin" && role === "sales_executive");

function signToken(user) {
  return jwt.sign({ sub: user._id.toString(), role: user.role }, JWT_SECRET, { expiresIn: process.env.JWT_EXPIRES_IN || "8h" });
}

async function findActiveBranch(id) {
  if (!id) return { error: "Choose a branch office." };
  if (!mongoose.isValidObjectId(id)) return { error: "Invalid branch." };
  const branch = await Branch.findById(id);
  if (!branch) return { error: "Branch not found." };
  if (!branch.active) return { error: `${branch.name} branch is inactive.` };
  return { branch };
}

async function availableStock(tokenKey) {
  const rows = await Entry.aggregate([
    { $match: { tokenKey } },
    { $group: { _id: "$type", quantity: { $sum: "$quantity" } } }
  ]);
  const of = type => rows.find(r => r._id === type)?.quantity || 0;
  return round(of("purchase") - of("sale"));
}

// ---------- middleware ----------
const auth = asyncRoute(async (req, res, next) => {
  const header = req.headers.authorization || "";
  const token = header.startsWith("Bearer ") ? header.slice(7) : "";
  if (!token) return res.status(401).json({ message: "Please sign in." });
  let payload;
  try { payload = jwt.verify(token, JWT_SECRET); }
  catch { return res.status(401).json({ message: "Session expired. Please sign in again." }); }
  const user = await User.findById(payload.sub).populate("branch");
  if (!user || !user.active) return res.status(401).json({ message: "Account unavailable." });
  if (user.passwordChangedAt && payload.iat < Math.floor(user.passwordChangedAt.getTime() / 1000)) {
    return res.status(401).json({ message: "Password was changed. Please sign in again." });
  }
  req.user = user;
  next();
});

const requireRole = (...roles) => (req, res, next) => {
  if (!roles.includes(req.user?.role)) return res.status(403).json({ message: "You don't have permission for this." });
  next();
};

const validId = (req, res, next) => {
  if (!mongoose.isValidObjectId(req.params.id)) return res.status(400).json({ message: "Invalid ID." });
  next();
};

// ---------- auth ----------
app.get("/api/health", (req, res) => res.json({
  ok: true, service: "token-tracker-api", version: "edit-route-v2",
  db: mongoose.connection.readyState === 1 ? "connected" : "disconnected"
}));

app.post("/api/auth/login", loginLimiter, asyncRoute(async (req, res) => {
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  if (!email || !password) return res.status(400).json({ message: "Email and password are required." });
  const user = await User.findOne({ email }).select("+passwordHash").populate("branch");
  if (!user || !user.active || !(await bcrypt.compare(password, user.passwordHash))) {
    return res.status(401).json({ message: "Invalid email or password." });
  }
  res.json({ token: signToken(user), user: publicUser(user) });
}));

app.get("/api/auth/me", auth, (req, res) => res.json({ user: publicUser(req.user) }));

app.post("/api/auth/change-password", auth, loginLimiter, asyncRoute(async (req, res) => {
  const currentPassword = String(req.body.currentPassword || "");
  const newPassword = String(req.body.newPassword || "");
  const user = await User.findById(req.user._id).select("+passwordHash");
  if (!currentPassword || !(await bcrypt.compare(currentPassword, user.passwordHash))) {
    return res.status(400).json({ message: "Current password is incorrect." });
  }
  if (newPassword.length < 10) return res.status(400).json({ message: "New password must be at least 10 characters." });
  user.passwordHash = await bcrypt.hash(newPassword, 12);
  user.passwordChangedAt = new Date(Date.now() - 1000);
  await user.save();
  res.json({ message: "Password updated. Other sessions have been signed out.", token: signToken(user) });
}));

// ---------- branches ----------
app.get("/api/branches", auth, asyncRoute(async (req, res) => {
  if (!isManager(req.user)) {
    return res.json({ branches: req.user.branch ? [{ ...publicBranch(req.user.branch), executives: null }] : [] });
  }
  const [branches, counts] = await Promise.all([
    Branch.find().sort({ name: 1 }),
    User.aggregate([{ $match: { role: "sales_executive", branch: { $ne: null } } }, { $group: { _id: "$branch", n: { $sum: 1 } } }])
  ]);
  const countMap = new Map(counts.map(c => [String(c._id), c.n]));
  res.json({ branches: branches.map(b => ({ ...publicBranch(b), executives: countMap.get(String(b._id)) || 0 })) });
}));

app.post("/api/branches", auth, requireRole("admin"), asyncRoute(async (req, res) => {
  const name = String(req.body.name || "").trim();
  const location = String(req.body.location || "").trim();
  if (!name || name.length > 100) return res.status(400).json({ message: "Enter a branch name (max 100 characters)." });
  const exists = await Branch.findOne({ nameKey: name.toLowerCase() });
  if (exists) return res.status(409).json({ message: "A branch with that name already exists." });
  const branch = await Branch.create({ name, location: location.slice(0, 200) });
  res.status(201).json({ branch: { ...publicBranch(branch), executives: 0 } });
}));

app.patch("/api/branches/:id", auth, requireRole("admin"), validId, asyncRoute(async (req, res) => {
  const branch = await Branch.findById(req.params.id);
  if (!branch) return res.status(404).json({ message: "Branch not found." });
  if (typeof req.body.name === "string" && req.body.name.trim()) {
    const name = req.body.name.trim().slice(0, 100);
    const clash = await Branch.findOne({ nameKey: name.toLowerCase(), _id: { $ne: branch._id } });
    if (clash) return res.status(409).json({ message: "A branch with that name already exists." });
    branch.name = name;
  }
  if (typeof req.body.location === "string") branch.location = req.body.location.trim().slice(0, 200);
  if (typeof req.body.active === "boolean") branch.active = req.body.active;
  await branch.save();
  res.json({ branch: publicBranch(branch) });
}));

app.delete("/api/branches/:id", auth, requireRole("admin"), validId, asyncRoute(async (req, res) => {
  const branch = await Branch.findById(req.params.id);
  if (!branch) return res.status(404).json({ message: "Branch not found." });
  const [users, entries] = await Promise.all([
    User.countDocuments({ branch: branch._id }),
    Entry.countDocuments({ branch: branch._id })
  ]);
  if (users || entries) {
    return res.status(409).json({ message: `${branch.name} has ${users} executive(s) and ${entries} sale(s). Mark it inactive instead.` });
  }
  await branch.deleteOne();
  res.json({ message: "Branch deleted." });
}));

// ---------- users ----------
app.get("/api/users", auth, requireRole(...MANAGERS), asyncRoute(async (req, res) => {
  const filter = req.user.role === "admin" ? {} : { role: "sales_executive" };
  const users = await User.find(filter).populate("branch").sort({ createdAt: -1 });
  res.json({ users: users.map(publicUser) });
}));

app.post("/api/users", auth, requireRole(...MANAGERS), asyncRoute(async (req, res) => {
  const name = String(req.body.name || "").trim();
  const email = String(req.body.email || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const role = req.body.role || "sales_executive";
  if (!ROLES.includes(role)) return res.status(400).json({ message: "Choose a valid role." });
  if (!canManageRole(req.user, role)) return res.status(403).json({ message: `You can't create a ${ROLE_LABEL[role]} account.` });
  if (!name || name.length > 100 || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) return res.status(400).json({ message: "Enter a valid name and email." });
  if (password.length < 10) return res.status(400).json({ message: "Password must be at least 10 characters." });
  let branch = null;
  if (role === "sales_executive") {
    const found = await findActiveBranch(req.body.branch);
    if (found.error) return res.status(400).json({ message: found.error });
    branch = found.branch._id;
  }
  if (await User.findOne({ email })) return res.status(409).json({ message: "An account with that email already exists." });
  const user = await User.create({ name, email, role, branch, passwordHash: await bcrypt.hash(password, 12) });
  await user.populate("branch");
  res.status(201).json({ user: publicUser(user) });
}));

app.patch("/api/users/:id", auth, requireRole(...MANAGERS), validId, asyncRoute(async (req, res) => {
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ message: "User not found." });
  if (!canManageRole(req.user, user.role)) return res.status(403).json({ message: "You can't change this account." });
  const isSelf = user._id.equals(req.user._id);
  const newRole = ROLES.includes(req.body.role) ? req.body.role : user.role;

  if (newRole !== user.role) {
    if (isSelf) return res.status(400).json({ message: "You cannot change your own role." });
    if (!canManageRole(req.user, newRole)) return res.status(403).json({ message: `You can't assign the ${ROLE_LABEL[newRole]} role.` });
  }
  if (isSelf && req.body.active === false) return res.status(400).json({ message: "You cannot deactivate your own account." });

  // Never leave the system without an active admin.
  if (user.role === "admin" && user.active && (newRole !== "admin" || req.body.active === false)) {
    const otherAdmins = await User.countDocuments({ role: "admin", active: true, _id: { $ne: user._id } });
    if (otherAdmins === 0) return res.status(400).json({ message: "At least one active admin is required." });
  }

  if (newRole === "sales_executive") {
    if (req.body.branch !== undefined || !user.branch) {
      const found = await findActiveBranch(req.body.branch);
      if (found.error) return res.status(400).json({ message: found.error });
      user.branch = found.branch._id;
    }
  } else {
    user.branch = null;
  }

  if (typeof req.body.name === "string" && req.body.name.trim()) user.name = req.body.name.trim().slice(0, 100);
  if (typeof req.body.active === "boolean") user.active = req.body.active;
  user.role = newRole;
  await user.save();
  await user.populate("branch");
  res.json({ user: publicUser(user) });
}));

app.delete("/api/users/:id", auth, requireRole(...MANAGERS), validId, asyncRoute(async (req, res) => {
  if (req.params.id === req.user._id.toString()) return res.status(400).json({ message: "You cannot delete your own account." });
  const user = await User.findById(req.params.id);
  if (!user) return res.status(404).json({ message: "User not found." });
  if (!canManageRole(req.user, user.role)) return res.status(403).json({ message: "You can't delete this account." });
  if (user.role === "admin" && user.active) {
    const otherAdmins = await User.countDocuments({ role: "admin", active: true, _id: { $ne: user._id } });
    if (otherAdmins === 0) return res.status(400).json({ message: "At least one active admin is required." });
  }
  const entryCount = await Entry.countDocuments({ createdBy: user._id });
  if (entryCount > 0) {
    return res.status(409).json({
      message: `This user has ${entryCount} ledger ${entryCount === 1 ? "entry" : "entries"}. Deactivate the account instead so the history stays intact.`
    });
  }
  await user.deleteOne();
  res.json({ message: "User deleted." });
}));

// ---------- entries ----------
// Admin + purchase admin see every entry; sales executives see only their own.
app.get("/api/entries", auth, asyncRoute(async (req, res) => {
  const filter = isManager(req.user) ? {} : { createdBy: req.user._id };
  if (["sale", "purchase"].includes(req.query.type)) filter.type = req.query.type;
  if (isManager(req.user) && req.query.branch) {
    if (!mongoose.isValidObjectId(req.query.branch)) return res.status(400).json({ message: "Invalid branch." });
    filter.branch = req.query.branch;
  }
  if (req.query.payment === "none") filter.paymentMethod = null;
  else if (PAYMENT_METHODS.includes(req.query.payment)) filter.paymentMethod = req.query.payment;
  const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 2000);
  const page = Math.max(parseInt(req.query.page, 10) || 1, 1);
  const [entries, total] = await Promise.all([
    Entry.find(filter)
      .populate("createdBy", "name email")
      .populate("branch", "name")
      .sort({ date: -1, createdAt: -1 })
      .skip((page - 1) * limit)
      .limit(limit),
    Entry.countDocuments(filter)
  ]);
  res.json({ entries, total, page, limit, pages: Math.max(Math.ceil(total / limit), 1) });
}));

const ALLOWED_TYPES = { admin: ["sale", "purchase"], purchase_admin: ["purchase"], sales_executive: ["sale"] };

app.post("/api/entries", auth, asyncRoute(async (req, res) => {
  const type = req.body.type;
  const token = String(req.body.token || "").trim();
  const quantity = Number(req.body.quantity);
  const rate = Number(req.body.rate);
  const date = new Date(req.body.date);
  const notes = String(req.body.notes || "").trim();
  const paymentMethod = req.body.paymentMethod;
  const paymentRef = String(req.body.paymentRef || "").trim();
  if (!["sale", "purchase"].includes(type)) return res.status(400).json({ message: "Type must be sale or purchase." });
  if (!ALLOWED_TYPES[req.user.role].includes(type)) {
    return res.status(403).json({ message: `A ${ROLE_LABEL[req.user.role]} can only record ${ALLOWED_TYPES[req.user.role].join(" and ")}s.` });
  }
  if (!token || token.length > 100) return res.status(400).json({ message: "Enter a token/product name (max 100 characters)." });
  if (!Number.isFinite(quantity) || quantity < MIN_QUANTITY) return res.status(400).json({ message: `Quantity must be at least ${MIN_QUANTITY}.` });
  if (!Number.isFinite(rate) || rate < 0) return res.status(400).json({ message: "Rate cannot be negative." });
  if (!req.body.date || Number.isNaN(date.getTime())) return res.status(400).json({ message: "Enter a valid date." });
  if (notes.length > 500) return res.status(400).json({ message: "Notes can be at most 500 characters." });
  if (!PAYMENT_METHODS.includes(paymentMethod)) return res.status(400).json({ message: "Choose a payment method." });
  if (paymentRef.length > 100) return res.status(400).json({ message: "Payment reference can be at most 100 characters." });

  let branch = null;
  if (type === "sale") {
    if (req.user.role === "sales_executive") {
      if (!req.user.branch) return res.status(400).json({ message: "You are not assigned to a branch office. Ask an admin to assign one." });
      if (!req.user.branch.active) return res.status(400).json({ message: `${req.user.branch.name} branch is inactive.` });
      branch = req.user.branch._id;
    } else {
      const found = await findActiveBranch(req.body.branch);
      if (found.error) return res.status(400).json({ message: found.error });
      branch = found.branch._id;
    }
    const available = await availableStock(tokenKeyOf(token));
    if (quantity > available + EPS) {
      return res.status(400).json({
        message: available > 0 ? `Only ${available} of "${token}" in stock.` : `"${token}" is out of stock. A purchase must be recorded first.`
      });
    }
  }

  const entry = await Entry.create({ type, token, quantity, rate, date, paymentMethod, paymentRef, notes, branch, createdBy: req.user._id });
  await entry.populate([{ path: "createdBy", select: "name email" }, { path: "branch", select: "name" }]);
  res.status(201).json({ entry });
}));

// Edit an entry (the ✓ button in the entries table).
// Accepts any of: date, token, quantity, rate, notes, paymentMethod, paymentRef, branch.
// Admin can edit any entry; everyone else only their own.
async function updateEntry(req, res) {
  const entry = await Entry.findById(req.params.id);
  if (!entry) return res.status(404).json({ message: "Entry not found. It may have been deleted — refresh the page." });
  if (req.user.role !== "admin" && !entry.createdBy.equals(req.user._id)) {
    return res.status(403).json({ message: "You can only edit your own entries." });
  }
  const b = req.body || {};
  if (b.type !== undefined && b.type !== entry.type) {
    return res.status(400).json({ message: "Type can't be changed. Delete this entry and add a new one instead." });
  }

  const token = b.token !== undefined ? String(b.token).trim() : entry.token;
  const quantity = b.quantity !== undefined ? Number(b.quantity) : entry.quantity;
  const rate = b.rate !== undefined ? Number(b.rate) : entry.rate;
  const date = b.date !== undefined ? new Date(b.date) : entry.date;
  const notes = b.notes !== undefined ? String(b.notes ?? "").trim() : entry.notes;
  const paymentRef = b.paymentRef !== undefined ? String(b.paymentRef ?? "").trim() : entry.paymentRef;
  const paymentMethod = b.paymentMethod !== undefined ? b.paymentMethod : entry.paymentMethod;

  if (!token || token.length > 100) return res.status(400).json({ message: "Enter a token/product name (max 100 characters)." });
  if (!Number.isFinite(quantity) || quantity < MIN_QUANTITY) return res.status(400).json({ message: `Quantity must be at least ${MIN_QUANTITY}.` });
  if (!Number.isFinite(rate) || rate < 0) return res.status(400).json({ message: "Rate cannot be negative." });
  if (Number.isNaN(new Date(date).getTime())) return res.status(400).json({ message: "Enter a valid date." });
  if (notes.length > 500) return res.status(400).json({ message: "Notes can be at most 500 characters." });
  if (b.paymentMethod !== undefined && !PAYMENT_METHODS.includes(paymentMethod)) return res.status(400).json({ message: "Choose a payment method." });
  if (paymentRef.length > 100) return res.status(400).json({ message: "Payment reference can be at most 100 characters." });

  // Managers may move a sale to another branch.
  let branch = entry.branch;
  if (entry.type === "sale" && b.branch !== undefined && isManager(req.user) && String(b.branch) !== String(entry.branch)) {
    const found = await findActiveBranch(b.branch);
    if (found.error) return res.status(400).json({ message: found.error });
    branch = found.branch._id;
  }

  // Stock checks
  const oldKey = entry.tokenKey;
  const newKey = tokenKeyOf(token);
  if (entry.type === "sale") {
    // This sale's own quantity is already counted as sold; add it back if the token stays the same.
    const available = (await availableStock(newKey)) + (newKey === oldKey ? entry.quantity : 0);
    if (quantity > available + EPS) {
      return res.status(400).json({
        message: available > 0 ? `Only ${round(available)} of "${token}" in stock.` : `"${token}" is out of stock.`
      });
    }
  } else {
    // A purchase can't be reduced or moved below what has already been sold from it.
    const available = await availableStock(oldKey);
    const removed = newKey === oldKey ? entry.quantity - quantity : entry.quantity;
    if (available - removed < -EPS) {
      return res.status(409).json({
        message: newKey === oldKey
          ? `Can't reduce below ${round(entry.quantity - available)}: that stock has already been sold.`
          : `Can't change the token: ${round(entry.quantity - available)} of "${entry.token}" from this purchase is already sold.`
      });
    }
  }

  entry.token = token;
  entry.quantity = quantity;
  entry.rate = rate;          // amount + tokenKey are recalculated by the model's pre("validate") hook
  entry.date = date;
  entry.notes = notes;
  entry.paymentMethod = paymentMethod;
  entry.paymentRef = paymentRef;
  entry.branch = branch;
  await entry.save();
  await entry.populate([{ path: "createdBy", select: "name email" }, { path: "branch", select: "name" }]);
  res.json({ entry });
}

// Registered for both PATCH and PUT so it works whichever the frontend uses.
app.patch("/api/entries/:id", auth, validId, asyncRoute(updateEntry));
app.put("/api/entries/:id", auth, validId, asyncRoute(updateEntry));

// Update how an entry was paid, e.g. settle an "on credit" sale once the customer pays.
app.patch("/api/entries/:id/payment", auth, validId, asyncRoute(async (req, res) => {
  const entry = await Entry.findById(req.params.id);
  if (!entry) return res.status(404).json({ message: "Entry not found." });
  if (req.user.role !== "admin" && !entry.createdBy.equals(req.user._id)) {
    return res.status(403).json({ message: "You can only update your own entries." });
  }
  const paymentMethod = req.body.paymentMethod;
  const paymentRef = String(req.body.paymentRef ?? entry.paymentRef ?? "").trim();
  if (!PAYMENT_METHODS.includes(paymentMethod)) return res.status(400).json({ message: "Choose a payment method." });
  if (paymentRef.length > 100) return res.status(400).json({ message: "Payment reference can be at most 100 characters." });
  entry.paymentMethod = paymentMethod;
  entry.paymentRef = paymentRef;
  await entry.save();
  await entry.populate([{ path: "createdBy", select: "name email" }, { path: "branch", select: "name" }]);
  res.json({ entry });
}));

app.delete("/api/entries/:id", auth, validId, asyncRoute(async (req, res) => {
  const entry = await Entry.findById(req.params.id);
  if (!entry) return res.status(404).json({ message: "Entry not found." });
  if (req.user.role !== "admin" && !entry.createdBy.equals(req.user._id)) {
    return res.status(403).json({ message: "You can only delete your own entries." });
  }
  if (entry.type === "purchase") {
    const available = await availableStock(entry.tokenKey);
    if (available - entry.quantity < -EPS) {
      return res.status(409).json({ message: `Can't delete: ${round(entry.quantity - available)} of this stock has already been sold. Delete those sales first.` });
    }
  }
  await entry.deleteOne();
  res.json({ message: "Entry deleted." });
}));

// ---------- stock ----------
app.get("/api/stock", auth, asyncRoute(async (req, res) => {
  const groups = await Entry.aggregate([
    { $group: { _id: { key: "$tokenKey", type: "$type", token: "$token" }, quantity: { $sum: "$quantity" }, amount: { $sum: "$amount" } } }
  ]);
  const byKey = new Map();
  for (const g of groups) {
    const { key, type, token } = g._id;
    const r = byKey.get(key) || { _id: key, token: token.trim(), nameQty: 0, purchased: 0, sold: 0, purchaseAmount: 0, salesAmount: 0 };
    if (type === "purchase") {
      r.purchased += g.quantity;
      r.purchaseAmount += g.amount;
      // Display the spelling used for the most purchased quantity.
      if (g.quantity > r.nameQty) { r.token = token.trim(); r.nameQty = g.quantity; }
    } else {
      r.sold += g.quantity;
      r.salesAmount += g.amount;
    }
    byKey.set(key, r);
  }
  const rows = [...byKey.values()].sort((a, b) => a.token.localeCompare(b.token));
  const manager = isManager(req.user);
  const stock = rows.map(r => {
    const available = round(r.purchased - r.sold);
    const base = { key: r._id, token: r.token, available };
    if (!manager) return base;
    const avgCost = r.purchased > 0 ? r.purchaseAmount / r.purchased : 0;
    return {
      ...base,
      purchased: round(r.purchased),
      sold: round(r.sold),
      avgCost: round(avgCost, 2),
      stockValue: round(available * avgCost, 2),
      salesAmount: round(r.salesAmount, 2)
    };
  });
  res.json({ stock });
}));

// ---------- reports ----------
app.get("/api/reports/summary", auth, asyncRoute(async (req, res) => {
  const manager = isManager(req.user);
  const match = manager ? {} : { createdBy: req.user._id };
  const rows = await Entry.aggregate([
    { $match: match },
    { $group: { _id: "$type", quantity: { $sum: "$quantity" }, amount: { $sum: "$amount" }, count: { $sum: 1 } } }
  ]);
  const summary = { sales: { quantity: 0, amount: 0, count: 0 }, purchases: { quantity: 0, amount: 0, count: 0 } };
  for (const row of rows) {
    summary[row._id === "sale" ? "sales" : "purchases"] = { quantity: round(row.quantity), amount: round(row.amount, 2), count: row.count };
  }
  summary.net = round(summary.sales.amount - summary.purchases.amount, 2);

  // Totals per payment method. "credit" sales are money still to collect; "credit" purchases are still to pay.
  const payGroups = await Entry.aggregate([
    { $match: match },
    { $group: { _id: { type: "$type", method: "$paymentMethod" }, amount: { $sum: "$amount" }, count: { $sum: 1 } } }
  ]);
  summary.byPayment = { sales: [], purchases: [] };
  for (const g of payGroups) {
    const bucket = g._id.type === "sale" ? "sales" : "purchases";
    summary.byPayment[bucket].push({ method: g._id.method ?? null, amount: round(g.amount, 2), count: g.count });
  }
  for (const list of Object.values(summary.byPayment)) list.sort((a, b) => b.amount - a.amount);
  const creditOf = list => list.find(p => p.method === "credit")?.amount || 0;
  summary.toCollect = creditOf(summary.byPayment.sales);
  summary.toPay = creditOf(summary.byPayment.purchases);

  if (manager) {
    const [groups, branches] = await Promise.all([
      Entry.aggregate([
        { $match: { type: "sale" } },
        { $group: { _id: "$branch", quantity: { $sum: "$quantity" }, amount: { $sum: "$amount" }, count: { $sum: 1 } } }
      ]),
      Branch.find({}, { name: 1 })
    ]);
    const names = new Map(branches.map(b => [String(b._id), b.name]));
    summary.byBranch = groups
      .map(g => ({ branchId: g._id, name: names.get(String(g._id)) || "No branch", quantity: round(g.quantity), amount: round(g.amount, 2), count: g.count }))
      .sort((a, b) => b.amount - a.amount);
  }
  if (req.user.role === "admin") {
    summary.users = await User.countDocuments();
    summary.branches = await Branch.countDocuments();
  }
  res.json({ summary });
}));

app.use("/api", (req, res) => res.status(404).json({ message: "Not found." }));

app.use((err, req, res, next) => {
  if (err?.message?.startsWith("CORS blocked origin:")) return res.status(403).json({ message: err.message });
  if (err?.type === "entity.parse.failed") return res.status(400).json({ message: "Invalid JSON body." });
  if (err?.name === "CastError") return res.status(400).json({ message: "Invalid ID or value." });
  if (err?.code === 11000) {
    const field = Object.keys(err.keyPattern || err.keyValue || {})[0];
    return res.status(409).json({ message: field === "nameKey" ? "A branch with that name already exists." : "That email already exists." });
  }
  if (err?.name === "ValidationError") {
    const first = Object.values(err.errors || {})[0];
    return res.status(400).json({ message: first?.message || "Invalid data." });
  }
  console.error(err);
  res.status(500).json({ message: "Unexpected server error." });
});

// One-time upgrades for data created by the earlier version of the app.
async function migrate() {
  const roles = await User.collection.updateMany({ role: "user" }, { $set: { role: "sales_executive", branch: null } });
  if (roles.modifiedCount) console.log(`Migrated ${roles.modifiedCount} "user" account(s) to sales_executive. Assign them a branch in the Users page.`);
  // Done in batches (not an update pipeline) so it also works on MongoDB-compatible hosts.
  let migrated = 0;
  let batch = [];
  const flush = async () => {
    if (!batch.length) return;
    await Entry.collection.bulkWrite(batch, { ordered: false });
    migrated += batch.length;
    batch = [];
  };
  const cursor = Entry.collection.find(
    { $or: [{ tokenKey: { $exists: false } }, { amount: { $exists: false } }] },
    { projection: { token: 1, branch: 1, quantity: 1, rate: 1 } }
  );
  for await (const doc of cursor) {
    const set = { tokenKey: tokenKeyOf(doc.token), amount: amountOf(doc.quantity, doc.rate) };
    if (doc.branch === undefined) set.branch = null;
    batch.push({ updateOne: { filter: { _id: doc._id }, update: { $set: set } } });
    if (batch.length >= 500) await flush();
  }
  await flush();
  if (migrated) console.log(`Upgraded ${migrated} existing entr${migrated === 1 ? "y" : "ies"} (stock key + amount).`);
}

export async function start() {
  await mongoose.connect(process.env.MONGODB_URI);
  console.log("MongoDB connected");
  await migrate();
  const email = String(process.env.ADMIN_EMAIL || "").trim().toLowerCase();
  const password = String(process.env.ADMIN_PASSWORD || "");
  if (email && password) {
    if (!(await User.findOne({ email }))) {
      await User.create({
        name: process.env.ADMIN_NAME || "Administrator",
        email,
        role: "admin",
        passwordHash: await bcrypt.hash(password, 12)
      });
      console.log(`Initial admin created for ${email}. Change this password after first sign-in.`);
    }
  } else {
    console.warn("ADMIN_EMAIL/ADMIN_PASSWORD not set; create an admin before production use.");
  }
  return app.listen(PORT, () => console.log(`Token Tracker API listening on port ${PORT}`));
}

start().catch(err => { console.error("Startup failed:", err.message); process.exit(1); });