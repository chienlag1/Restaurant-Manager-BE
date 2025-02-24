const mongoose = require("mongoose");

const adminSchema = new mongoose.Schema(
  {
    username: { type: String, required: true },
    email: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    role: { type: String, default: "admin" },
    avatar: { type: String, default: "/uploads/default-avatar.png" },
  },
  { timestamps: true }
);

module.exports = mongoose.model("Admin", adminSchema);
