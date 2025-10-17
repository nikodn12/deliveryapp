require('dotenv').config();
const express = require('express');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const path = require('path'); // TAMBAHKAN INI
const db = require('./database');

const app = express();
const PORT = process.env.PORT || 5000;
const JWT_SECRET = process.env.JWT_SECRET || 'your-secret-key-change-in-production';

// Middleware
app.use(cors({
  origin: true,
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: ['Content-Type', 'Authorization']
}));
app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// Logging middleware
app.use((req, res, next) => {
  console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
  next();
});

// ==================== AUTH ROUTES ====================

// Route untuk login
app.post('/api/login', (req, res) => {
  const { username, password } = req.body;

  // Validasi input
  if (!username || !password) {
    return res.status(400).json({ 
      success: false,
      message: 'Username dan password harus diisi' 
    });
  }

  // Cari user di database
  db.get('SELECT * FROM users WHERE username = ?', [username], (err, user) => {
    if (err) {
      console.error('Database error:', err);
      return res.status(500).json({ 
        success: false,
        message: 'Terjadi kesalahan server' 
      });
    }

    if (!user) {
      return res.status(401).json({ 
        success: false,
        message: 'Username atau password salah' 
      });
    }

    // Cek status user
    if (user.status !== 'aktif') {
      return res.status(403).json({ 
        success: false,
        message: 'Akun Anda tidak aktif. Hubungi administrator.' 
      });
    }

    // Verifikasi password
    const isValidPassword = bcrypt.compareSync(password, user.password);
    
    if (!isValidPassword) {
      return res.status(401).json({ 
        success: false,
        message: 'Username atau password salah' 
      });
    }

    // Buat token JWT
    const token = jwt.sign(
      { 
        id: user.id, 
        username: user.username, 
        role: user.role 
      },
      JWT_SECRET,
      { expiresIn: '24h' }
    );

    // Kirim response
    res.json({
      success: true,
      message: 'Login berhasil',
      token,
      user: {
        id: user.id,
        username: user.username,
        role: user.role,
        nama_lengkap: user.nama_lengkap,
        email: user.email,
        telepon: user.telepon
      }
    });
  });
});

// ==================== MIDDLEWARE ====================

// Middleware untuk verifikasi token
const verifyToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (!token) {
    return res.status(403).json({ 
      success: false,
      message: 'Token tidak ditemukan' 
    });
  }

  jwt.verify(token, JWT_SECRET, (err, decoded) => {
    if (err) {
      return res.status(401).json({ 
        success: false,
        message: 'Token tidak valid atau sudah kadaluarsa' 
      });
    }
    req.user = decoded;
    next();
  });
};

// Middleware untuk verifikasi role admin
const verifyAdmin = (req, res, next) => {
  if (req.user.role !== 'admin') {
    return res.status(403).json({ 
      success: false,
      message: 'Akses ditolak. Hanya admin yang dapat mengakses.' 
    });
  }
  next();
};

// ==================== USER ROUTES ====================

// Get profile user yang sedang login
app.get('/api/profile', verifyToken, (req, res) => {
  db.get(
    'SELECT id, username, role, nama_lengkap, email, telepon, status, created_at FROM users WHERE id = ?', 
    [req.user.id], 
    (err, user) => {
      if (err) {
        return res.status(500).json({ 
          success: false,
          message: 'Terjadi kesalahan server' 
        });
      }
      
      if (!user) {
        return res.status(404).json({ 
          success: false,
          message: 'User tidak ditemukan' 
        });
      }

      res.json({ 
        success: true,
        user 
      });
    }
  );
});

// Get semua users (hanya admin)
app.get('/api/users', verifyToken, verifyAdmin, (req, res) => {
  const { role } = req.query;
  
  let query = 'SELECT id, username, role, nama_lengkap, email, telepon, status, created_at FROM users';
  let params = [];
  
  if (role) {
    query += ' WHERE role = ?';
    params.push(role);
  }
  
  query += ' ORDER BY created_at DESC';
  
  db.all(query, params, (err, users) => {
    if (err) {
      return res.status(500).json({ 
        success: false,
        message: 'Terjadi kesalahan server' 
      });
    }
    
    res.json({ 
      success: true,
      data: users,
      total: users.length
    });
  });
});

// Get user by ID (hanya admin)
app.get('/api/users/:id', verifyToken, verifyAdmin, (req, res) => {
  const { id } = req.params;
  
  db.get(
    'SELECT id, username, role, nama_lengkap, email, telepon, status, created_at FROM users WHERE id = ?',
    [id],
    (err, user) => {
      if (err) {
        return res.status(500).json({ 
          success: false,
          message: 'Terjadi kesalahan server' 
        });
      }
      
      if (!user) {
        return res.status(404).json({ 
          success: false,
          message: 'User tidak ditemukan' 
        });
      }
      
      res.json({ 
        success: true,
        data: user 
      });
    }
  );
});

// Update user (admin bisa update semua, user biasa hanya bisa update diri sendiri)
app.put('/api/users/:id', verifyToken, (req, res) => {
  const { id } = req.params;
  const { nama_lengkap, email, telepon, password } = req.body;
  
  // Cek authorization
  if (req.user.role !== 'admin' && req.user.id != id) {
    return res.status(403).json({ 
      success: false,
      message: 'Anda tidak memiliki akses untuk mengubah data user ini' 
    });
  }
  
  let updates = [];
  let params = [];
  
  if (nama_lengkap) {
    updates.push('nama_lengkap = ?');
    params.push(nama_lengkap);
  }
  
  if (email) {
    updates.push('email = ?');
    params.push(email);
  }
  
  if (telepon) {
    updates.push('telepon = ?');
    params.push(telepon);
  }
  
  if (password) {
    updates.push('password = ?');
    params.push(bcrypt.hashSync(password, 10));
  }
  
  if (updates.length === 0) {
    return res.status(400).json({ 
      success: false,
      message: 'Tidak ada data yang diupdate' 
    });
  }
  
  updates.push('updated_at = CURRENT_TIMESTAMP');
  params.push(id);
  
  const query = `UPDATE users SET ${updates.join(', ')} WHERE id = ?`;
  
  db.run(query, params, function(err) {
    if (err) {
      return res.status(500).json({ 
        success: false,
        message: 'Gagal mengupdate user' 
      });
    }
    
    res.json({ 
      success: true,
      message: 'Data user berhasil diupdate' 
    });
  });
});

// ==================== STATISTICS ROUTES ====================

// Get dashboard statistics
app.get('/api/statistics', verifyToken, (req, res) => {
  const stats = {};
  
  // Total pengiriman
  db.get('SELECT COUNT(*) as total FROM pengiriman', (err, result) => {
    if (err) {
      return res.status(500).json({ 
        success: false,
        message: 'Gagal mengambil statistik' 
      });
    }
    
    stats.total_pengiriman = result.total;
    
    // Total kurir aktif
    db.get("SELECT COUNT(*) as total FROM users WHERE role = 'kurir' AND status = 'aktif'", (err, result) => {
      if (err) {
        return res.status(500).json({ 
          success: false,
          message: 'Gagal mengambil statistik' 
        });
      }
      
      stats.total_kurir = result.total;
      
      // Pengiriman hari ini
      db.get(
        "SELECT COUNT(*) as total FROM pengiriman WHERE DATE(created_at) = DATE('now')",
        (err, result) => {
          if (err) {
            return res.status(500).json({ 
              success: false,
              message: 'Gagal mengambil statistik' 
            });
          }
          
          stats.pengiriman_hari_ini = result.total;
          
          // Pengiriman selesai hari ini
          db.get(
            "SELECT COUNT(*) as total FROM pengiriman WHERE status = 'selesai' AND DATE(updated_at) = DATE('now')",
            (err, result) => {
              if (err) {
                return res.status(500).json({ 
                  success: false,
                  message: 'Gagal mengambil statistik' 
                });
              }
              
              stats.selesai_hari_ini = result.total;
              
              res.json({ 
                success: true,
                data: stats 
              });
            }
          );
        }
      );
    });
  });
});

// ==================== HEALTH CHECK ====================

app.get('/api/health', (req, res) => {
  res.json({ 
    success: true,
    status: 'OK', 
    message: 'Server is running',
    timestamp: new Date().toISOString()
  });
});

// ==================== SERVE REACT STATIC FILES ====================
// TAMBAHKAN KODE INI DI BAWAH SEMUA ROUTE API

// Serve static files dari React build
app.use(express.static(path.join(__dirname, '../frontend/build')));

// Handle React Router - semua route yang tidak match dengan API akan serve index.html
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, '../frontend/build/index.html'));
});

// ==================== ERROR HANDLERS ====================

// 404 handler untuk API (seharusnya tidak tercapai karena app.get('*') di atas)
app.use((req, res) => {
  res.status(404).json({ 
    success: false,
    message: 'Endpoint tidak ditemukan' 
  });
});

// Error handler
app.use((err, req, res, next) => {
  console.error('Error:', err);
  res.status(500).json({ 
    success: false,
    message: 'Terjadi kesalahan server' 
  });
});

// Dari:
app.listen(PORT, () => {
  console.log(`🚀 Server berjalan di http://localhost:${PORT}`);
});

// Jadi (tambahkan '0.0.0.0'):
app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server berjalan di http://0.0.0.0:${PORT}`);
  console.log(`🌍 Dapat diakses dari jaringan eksternal`);
});

// Graceful shutdown
process.on('SIGINT', () => {
  console.log('\n👋 Shutting down server...');
  db.close((err) => {
    if (err) {
      console.error('Error closing database:', err);
    } else {
      console.log('✅ Database connection closed');
    }
    process.exit(0);
  });
});