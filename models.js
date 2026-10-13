import mongoose from "mongoose";

export const ROLES = ["admin", "purchase_admin", "sales_executive"];
// "credit" = not paid yet (pay later / udhaar).
export const PAYMENT_METHODS = ["cash", "upi", "bank_transfer", "card", "cheque", "credit"];
export const tokenKeyOf = token => String(token || "").trim().toLowerCase();

const branchSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  // Lower-cased name so "Ameerpet" and "ameerpet" can't both exist.
  nameKey: { type: String, required: true, unique: true },
  location: { type: String, trim: true, maxlength: 200, default: "" },
  active: { type: Boolean, default: true }
}, { timestamps: true });

branchSchema.pre("validate", function setNameKey(next) {
  if (this.name) this.nameKey = this.name.trim().toLowerCase();
  next();
});

const userSchema = new mongoose.Schema({
  name: { type: String, required: true, trim: true, maxlength: 100 },
  email: { type: String, required: true, unique: true, lowercase: true, trim: true },
  passwordHash: { type: String, required: true, select: false },
  passwordChangedAt: { type: Date, default: null },
  role: { type: String, enum: ROLES, default: "sales_executive" },
  // Only sales executives belong to a branch office.
  branch: { type: mongoose.Schema.Types.ObjectId, ref: "Branch", default: null },
  active: { type: Boolean, default: true }
}, { timestamps: true });

const entrySchema = new mongoose.Schema({
  type: { type: String, enum: ["sale", "purchase"], required: true },
  token: { type: String, required: true, trim: true, maxlength: 100 },
  // Lower-cased token name, used to match stock across entries ("Gold" == "gold").
  tokenKey: { type: String, required: true, index: true },
  quantity: { type: Number, required: true, min: 0.0001 },
  rate: { type: Number, required: true, min: 0 },
  // quantity × rate, stored so reports don't recompute it.
  amount: { type: Number, required: true, min: 0 },
  date: { type: Date, required: true },
  // How it was paid. Null only on entries recorded before this field existed.
  paymentMethod: { type: String, enum: [...PAYMENT_METHODS, null], default: null },
  // UPI transaction ID, cheque number, bank reference, etc.
  paymentRef: { type: String, trim: true, maxlength: 100, default: "" },
  notes: { type: String, trim: true, maxlength: 500, default: "" },
  // Set for sales (the branch that sold); null for purchases (main office).
  branch: { type: mongoose.Schema.Types.ObjectId, ref: "Branch", default: null },
  createdBy: { type: mongoose.Schema.Types.ObjectId, ref: "User", required: true }
}, { timestamps: true });

export const amountOf = (quantity, rate) => Math.round(Number(quantity) * Number(rate) * 100) / 100;

entrySchema.pre("validate", function setDerived(next) {
  if (this.token) this.tokenKey = tokenKeyOf(this.token);
  if (Number.isFinite(this.quantity) && Number.isFinite(this.rate)) this.amount = amountOf(this.quantity, this.rate);
  next();
});

entrySchema.index({ date: -1 });
entrySchema.index({ createdBy: 1, date: -1 });
entrySchema.index({ branch: 1, date: -1 });

export const Branch = mongoose.model("Branch", branchSchema);
export const User = mongoose.model("User", userSchema);
export const Entry = mongoose.model("Entry", entrySchema);
