require("dotenv").config();

const bcrypt = require("bcrypt");
const jwt = require("jsonwebtoken");
const Admin = require("../models/Admin");
const User = require("../models/User");
const Table = require("../models/Table");

// Đăng ký admin
exports.registerAdmin = async (req, res) => {
  const { username, email, password } = req.body;
  if (!username || !email || !password) {
    return res.status(400).json({ message: "Missing required fields" });
  }
  const existingAdmin = await Admin.findOne({ email });
  if (existingAdmin) {
    return res.status(400).json({ message: "Admin already exists" });
  }
  if (!email.endsWith("@admin.com")) {
    return res.status(400).json({ message: "Email must end with @admin.com" });
  }
  const hashedPassword = await bcrypt.hash(password, 10);
  const admin = new Admin({
    username,
    email,
    passwordHash: hashedPassword,
    role: "admin",
  });
  await admin.save();
  res.status(201).json({ message: "Admin registered successfully", admin });
};

// Đăng nhập admin
exports.loginAdmin = async (req, res) => {
  const { email, password } = req.body;
  if (!email || !password) {
    return res.status(400).json({ message: "Missing email or password" });
  }
  try {
    const admin = await Admin.findOne({ email });
    if (!admin) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    const isMatch = await bcrypt.compare(password, admin.passwordHash);
    if (!isMatch) {
      return res.status(400).json({ message: "Invalid email or password" });
    }
    const token = jwt.sign(
      { userId: admin._id, role: admin.role },
      process.env.JWT_SECRET,
      { expiresIn: "1h" }
    );
    res.status(200).json({
      message: "Login successful",
      token,
      role: admin.role,
      userId: admin._id,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Internal server error" });
  }
};

// Lấy danh sách admin
exports.getAdmins = async (req, res) => {
  try {
    const admins = await Admin.find().select("-passwordHash");
    if (!admins || admins.length === 0) {
      return res.status(404).json({ message: "No admins found" });
    }
    res.status(200).json({ admins });
  } catch (error) {
    res.status(500).json({ message: "Error fetching admins", error });
  }
};
// Lấy thông tin admin
exports.getAdminProfile = async (req, res) => {
  const authHeader = req.headers.authorization;
  if (!authHeader) {
    return res.status(401).json({ message: "Authorization token is missing" });
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    const admin = await Admin.findById(decoded.userId).select("-passwordHash"); // Fetch admin by decoded userId
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }
    res.status(200).json(admin);
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error fetching admin profile", error });
  }
};

// Cập nhật thông tin admin
exports.updateAdmin = async (req, res) => {
  const { id } = req.params;
  const { username, email, password } = req.body;
  const existingAdmin = await Admin.findOne({ email });
  if (existingAdmin && existingAdmin._id.toString() !== id) {
    return res
      .status(400)
      .json({ message: "Email already in use by another admin" });
  }
  const updateData = { username, email };
  if (password) {
    updateData.passwordHash = await bcrypt.hash(password, 10);
  }
  try {
    const updatedAdmin = await Admin.findByIdAndUpdate(id, updateData, {
      new: true,
    }).select("-passwordHash");
    if (!updatedAdmin) {
      return res.status(404).json({ message: "Admin not found" });
    }
    res
      .status(200)
      .json({ message: "Admin updated successfully", updatedAdmin });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error updating admin", error });
  }
};

// Xóa admin
exports.deleteAdmin = async (req, res) => {
  const { id } = req.params;
  const deletedAdmin = await Admin.findByIdAndDelete(id);
  if (!deletedAdmin) {
    return res.status(404).json({ message: "Admin not found" });
  }
  res.status(200).json({ message: "Admin deleted successfully" });
};

// Middleware xác thực admin
exports.isAdmin = (req, res, next) => {
  const token = req.headers.authorization?.split(" ")[1];
  if (!token) {
    return res
      .status(401)
      .json({ message: "Access denied. No token provided" });
  }
  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    if (decoded.role !== "admin") {
      return res.status(403).json({ message: "Access denied. Admins only" });
    }
    req.admin = decoded;
    next();
  } catch (error) {
    res.status(400).json({ message: "Invalid token" });
  }
};

// Lấy danh sách tất cả người dùng
exports.getAllUsers = async (req, res) => {
  try {
    const users = await User.find().select("-passwordHash");
    if (!users || users.length === 0) {
      return res.status(404).json({ message: "No users found" });
    }
    res.status(200).json({ users });
  } catch (error) {
    res.status(500).json({ message: "Error fetching users", error });
  }
};

// API: Lấy tất cả Admins và Users
exports.getAllAdminsAndUsers = async (req, res) => {
  try {
    const admins = await Admin.find().select("-passwordHash");
    const users = await User.find().select("-passwordHash");
    if (!admins.length && !users.length) {
      return res.status(404).json({ message: "No admins or users found" });
    }
    res.status(200).json({ admins, users });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error fetching admins and users", error });
  }
};

// API: Nâng cấp user lên admin
exports.upgradeUserToAdmin = async (req, res) => {
  const { id } = req.params;
  try {
    const user = await User.findById(id);
    if (!user) {
      return res.status(404).json({ message: "User not found" });
    }
    if (user.role === "admin") {
      return res.status(400).json({ message: "User is already an admin" });
    }
    user.role = "admin";
    await user.save();
    res
      .status(200)
      .json({ message: "User upgraded to admin successfully", user });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error upgrading user to admin", error });
  }
};

// API: Xóa user
exports.deleteUser = async (req, res) => {
  const { id } = req.params;
  try {
    const deletedUser = await User.findByIdAndDelete(id);
    if (!deletedUser) {
      return res.status(404).json({ message: "User not found" });
    }
    res.status(200).json({ message: "User deleted successfully" });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ message: "Error deleting user", error: error.message });
  }
};

// API: Thay đổi mật khẩu admin

exports.changeAdminPassword = async (req, res) => {
  const { oldPassword, newPassword } = req.body;

  // Check if old password and new password are provided
  if (!oldPassword || !newPassword) {
    return res
      .status(400)
      .json({ message: "Both old and new passwords are required" });
  }

  try {
    // Find the admin by the ID from the JWT token
    const admin = await Admin.findById(req.admin.userId);
    if (!admin) {
      return res.status(404).json({ message: "Admin not found" });
    }

    // Compare the old password with the stored password hash
    const isMatch = await bcrypt.compare(oldPassword, admin.passwordHash);
    if (!isMatch) {
      return res.status(400).json({ message: "Old password is incorrect" });
    }

    // Hash the new password and update it
    const hashedPassword = await bcrypt.hash(newPassword, 10);
    admin.passwordHash = hashedPassword;
    await admin.save();

    res.status(200).json({ message: "Password updated successfully" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Error updating password", error });
  }
};

// API: Thêm bàn dựa trên số lượng
exports.addTable = async (req, res) => {
  const { quantity } = req.body;

  if (!quantity || typeof quantity !== "number" || quantity <= 0) {
    return res.status(400).json({
      message: "Quantity is required and must be a positive number",
    });
  }

  try {
    // Lấy tất cả các bàn hiện có, sắp xếp theo thứ tự tăng dần của tableNumber
    const existingTables = await Table.find().sort({ tableNumber: 1 }).exec();
    const existingNumbers = existingTables.map((t) => t.tableNumber);

    // Xác định số lớn nhất hiện có
    const max = existingNumbers.length > 0 ? Math.max(...existingNumbers) : 0;

    // Tìm các số bị thiếu trong chuỗi từ 1 đến max
    const missingNumbers = [];
    for (let i = 1; i <= max; i++) {
      if (!existingNumbers.includes(i)) {
        missingNumbers.push(i);
      }
    }

    // Xác định các số bàn cho các bàn mới cần tạo
    let newNumbers = [];
    if (missingNumbers.length >= quantity) {
      newNumbers = missingNumbers.slice(0, quantity);
    } else {
      newNumbers = [...missingNumbers];
      const remaining = quantity - missingNumbers.length;
      for (let i = 1; i <= remaining; i++) {
        newNumbers.push(max + i);
      }
    }

    // Tạo mảng các bàn mới với các số tableNumber được xác định
    const newTables = newNumbers.map((num) => ({
      tableNumber: num,
      numberOfPeople: 0, // Giá trị mặc định
      dateTime: new Date(), // Giá trị mặc định là thời gian hiện tại
      // Các trường khác (customerName, phoneNumber, note) có thể cập nhật sau nếu cần
    }));

    const insertedTables = await Table.insertMany(newTables);
    // Sắp xếp lại theo tableNumber tăng dần
    const sortedTables = insertedTables.sort(
      (a, b) => a.tableNumber - b.tableNumber
    );

    res.status(201).json({
      message: "Tables created successfully",
      tables: sortedTables,
    });
  } catch (error) {
    console.error(error);
    res.status(500).json({
      message: "Error creating tables",
      error: error.message,
    });
  }
};

// API lấy danh sách bàn – READ
exports.getTables = async (req, res) => {
  try {
    const tables = await Table.find();
    if (!tables || tables.length === 0) {
      return res.status(404).json({ message: "Không tìm thấy bàn nào" });
    }
    res.status(200).json({ tables });
  } catch (error) {
    res
      .status(500)
      .json({ message: "Lỗi khi lấy danh sách bàn", error: error.message });
  }
};

// API cập nhật thông tin bàn – UPDATE
exports.updateTable = async (req, res) => {
  const { id } = req.params;
  const {
    customerName,
    phoneNumber,
    numberOfPeople,
    dateTime,
    note,
    email,
    name,
  } = req.body;
  try {
    const table = await Table.findById(id);
    if (!table) {
      return res.status(404).json({ message: "Không tìm thấy bàn" });
    }
    // Cập nhật các trường nếu có dữ liệu mới
    table.customerName = customerName || table.customerName;
    table.phoneNumber = phoneNumber || table.phoneNumber;
    table.numberOfPeople = numberOfPeople || table.numberOfPeople;
    table.dateTime = dateTime || table.dateTime;
    table.note = note || table.note;
    await table.save();
    res.status(200).json({ message: "Cập nhật bàn thành công", table });
  } catch (error) {
    console.error(error);
    res
      .status(500)
      .json({ message: "Lỗi khi cập nhật bàn", error: error.message });
  }
};

// API xóa bàn – DELETE
exports.deleteTable = async (req, res) => {
  const { id } = req.params;
  try {
    const deletedTable = await Table.findByIdAndDelete(id);
    if (!deletedTable) {
      return res.status(404).json({ message: "Không tìm thấy bàn" });
    }
    res.status(200).json({ message: "Xóa bàn thành công" });
  } catch (error) {
    console.error(error);
    res.status(500).json({ message: "Lỗi khi xóa bàn", error: error.message });
  }
};
exports.uploadAvatarAdmin = async (req, res) => {
  try {
    if (!req.file) {
      return res.status(400).json({ error: "No file uploaded" });
    }

    // Lấy đường dẫn ảnh đã upload
    const avatarUrl = `/uploads/${req.file.filename}`;

    // Cập nhật avatar cho admin
    const admin = await Admin.findById(req.admin.userId); // Lấy admin từ token
    if (!admin) {
      return res.status(404).json({ error: "Admin not found" });
    }

    // Cập nhật avatar trong cơ sở dữ liệu
    admin.avatar = avatarUrl;
    await admin.save();

    res.json({ avatarUrl });
  } catch (error) {
    console.error("Error uploading avatar:", error);
    res.status(500).json({ error: "Error uploading avatar" });
  }
};