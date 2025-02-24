const express = require("express");
const {
  registerAdmin,
  loginAdmin,
  getAdmins,
  updateAdmin,
  deleteAdmin,
  isAdmin,
  getAllUsers,
  getAllAdminsAndUsers,
  upgradeUserToAdmin,
  addTable,
  getTables,
  updateTable,
  deleteTable,
  deleteUser,
  getAdminProfile,
  changeAdminPassword,
  uploadAvatarAdmin,
  } = require("../controllers/AdminController");
const upload = require("../config/multerConfig");
const { authenticateToken } = require("../middlewares/authenticateToken");
const router = express.Router();

// Route cho Admin
router.post("/register", registerAdmin);
router.post("/login", loginAdmin);
router.get("/", isAdmin, getAdmins);
router.get("/users", isAdmin, getAllUsers);
router.get("/all", isAdmin, getAllAdminsAndUsers);
router.put("/updateRole/:id", isAdmin, upgradeUserToAdmin);
router.delete("/users/:id", isAdmin, deleteUser);
router.delete("/:id", isAdmin, deleteAdmin);

// Route lấy và cập nhật thông tin admin
router.get("/profile", isAdmin, getAdminProfile); // Lấy thông tin admin theo ID
router.put("/profile/:id", isAdmin, updateAdmin);
// Route: Thay đổi mật khẩu admin
router.put("/editPass", isAdmin, changeAdminPassword);

// Route cho Table
router.post("/tables", isAdmin, addTable);
router.get("/tables", isAdmin, getTables);
router.put("/tables/:id", isAdmin, updateTable);
router.delete("/tables/:id", isAdmin, deleteTable);

// Route upload avatar admin
router.post("/upload-avatar-admin", upload.single("profile-image"), isAdmin, uploadAvatarAdmin);

module.exports = router;
