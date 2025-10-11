const sqlite3 = require('sqlite3').verbose();
const bcrypt = require('bcryptjs');
const path = require('path');

// Path database
const dbPath = path.join(__dirname, 'delivery.db');

// Buat koneksi database
const db = new sqlite3.Database(dbPath, (err) => {
  if (err) {
    console.error('❌ Error opening database:', err.message);
  } else {
    console.log('✅ Connected to SQLite database');
    initializeDatabase();
  }
});

// Inisialisasi database dan buat tabel-tabel
function initializeDatabase() {
  // Tabel users
  db.run(`CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    password TEXT NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('admin', 'kurir')),
    nama_lengkap TEXT NOT NULL,
    email TEXT,
    telepon TEXT,
    status TEXT DEFAULT 'aktif' CHECK(status IN ('aktif', 'nonaktif')),
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP
  )`, (err) => {
    if (err) {
      console.error('❌ Error creating users table:', err.message);
    } else {
      console.log('✅ Users table ready');
      createDefaultUsers();
    }
  });

  // Tabel pengiriman (untuk fitur kedepan)
  db.run(`CREATE TABLE IF NOT EXISTS pengiriman (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    nomor_resi TEXT UNIQUE NOT NULL,
    pengirim TEXT NOT NULL,
    penerima TEXT NOT NULL,
    alamat_penerima TEXT NOT NULL,
    telepon_penerima TEXT NOT NULL,
    kurir_id INTEGER,
    status TEXT DEFAULT 'pending' CHECK(status IN ('pending', 'diproses', 'dikirim', 'selesai', 'dibatalkan')),
    berat REAL,
    catatan TEXT,
    created_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    updated_at DATETIME DEFAULT CURRENT_TIMESTAMP,
    FOREIGN KEY (kurir_id) REFERENCES users(id)
  )`, (err) => {
    if (err) {
      console.error('❌ Error creating pengiriman table:', err.message);
    } else {
      console.log('✅ Pengiriman table ready');
    }
  });
}

// Buat user default untuk testing
function createDefaultUsers() {
  const defaultUsers = [
    { 
      username: 'admin', 
      password: 'admin123', 
      role: 'admin', 
      nama_lengkap: 'Administrator',
      email: 'admin@delivery.com',
      telepon: '081234567890'
    },
    { 
      username: 'kurir1', 
      password: 'kurir123', 
      role: 'kurir', 
      nama_lengkap: 'Kurir Satu',
      email: 'kurir1@delivery.com',
      telepon: '081234567891'
    },
    { 
      username: 'kurir2', 
      password: 'kurir123', 
      role: 'kurir', 
      nama_lengkap: 'Kurir Dua',
      email: 'kurir2@delivery.com',
      telepon: '081234567892'
    }
  ];

  defaultUsers.forEach(user => {
    db.get('SELECT id FROM users WHERE username = ?', [user.username], (err, row) => {
      if (err) {
        console.error('❌ Error checking user:', err.message);
        return;
      }
      
      if (!row) {
        const hashedPassword = bcrypt.hashSync(user.password, 10);
        db.run(
          `INSERT INTO users (username, password, role, nama_lengkap, email, telepon) 
           VALUES (?, ?, ?, ?, ?, ?)`,
          [user.username, hashedPassword, user.role, user.nama_lengkap, user.email, user.telepon],
          (err) => {
            if (err) {
              console.error('❌ Error creating default user:', err.message);
            } else {
              console.log(`✅ Default user created: ${user.username} (${user.role})`);
            }
          }
        );
      }
    });
  });
}

// Export database connection
module.exports = db;