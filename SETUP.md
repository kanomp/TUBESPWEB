# Setup Database - Pembunuh Bayaran E-Commerce

## Option 1: Manual Setup (Recommended)

### Step 1: Create Database
```sql
CREATE DATABASE IF NOT EXISTS tubes_ecommerce;
USE tubes_ecommerce;
```

### Step 2: Import Schema
- Open phpMyAdmin (http://localhost/phpmyadmin)
- Click "Import" tab
- Choose file: `database/schema.sql`
- Click Import

### Step 3: Import Sample Data
- Click "Import" tab again
- Choose file: `database/seeders.sql`
- Click Import

### Step 4: Verify
```sql
SELECT COUNT(*) as users FROM users;
SELECT COUNT(*) as products FROM products;
```

## Option 2: Command Line Setup

### Windows (Command Prompt)
```bash
cd c:\laragon\www\TubesPWEB

# Create database and import
mysql -u root -p tubes_ecommerce < database/schema.sql
mysql -u root -p tubes_ecommerce < database/seeders.sql
```

### Linux/Mac (Terminal)
```bash
cd /path/to/TubesPWEB

mysql -u root -p tubes_ecommerce < database/schema.sql
mysql -u root -p tubes_ecommerce < database/seeders.sql
```

## Verify Installation

1. Open browser: http://localhost/TubesPWEB
2. You should see home page
3. Try login dengan admin account:
   - Email: admin@pembunuhbayaran.com
   - Password: password

## Common Issues & Solutions

### Issue: "Connection Failed"
**Solution:** Check database credentials in `config/config.php`
```php
define('DB_HOST', 'localhost');
define('DB_USER', 'root');
define('DB_PASS', '');
define('DB_NAME', 'tubes_ecommerce');
```

### Issue: "Table not found"
**Solution:** Re-import schema.sql file:
- Go to phpMyAdmin
- Select database: tubes_ecommerce
- Click Import
- Upload schema.sql

### Issue: "404 Page Not Found"
**Solution:** 
1. Check `.htaccess` dalam folder
2. Enable mod_rewrite di Apache
3. Restart Apache/Laragon

### Issue: Blank Admin Page
**Solution:**
- Check if database imported successfully
- Verify database connection

## Default Login Credentials

### Admin
- Email: admin@pembunuhbayaran.com
- Password: password

### Sample Customer
- Email: john@example.com
- Password: password

**Note:** Passwords dalam database sudah di-hash dengan Bcrypt. Jika ingin membuat user baru dengan password spesifik, hash dulu dengan `password_hash('password', PASSWORD_BCRYPT)`.

## Next Steps

1. Login ke admin panel: http://localhost/TubesPWEB/admin/dashboard
2. Create some products
3. Register as customer
4. Test shopping flow

Enjoy! 🎉
