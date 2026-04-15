# Pembunuh Bayaran - E-Commerce Website

Website e-commerce Demo untuk Tugas Besar dengan tema "Pembunuh Bayaran" (hanya untuk keperluan tugas).

## Fitur Utama

### Customer Side
- ✅ Halaman Home dengan product listing
- ✅ Search dan Filter by Category
- ✅ Product Detail dengan Reviews dan Ratings
- ✅ Shopping Cart Management
- ✅ Checkout Process
- ✅ Dummy Payment System
- ✅ Order Tracking
- ✅ Wishlist
- ✅ Loyalty Points System
- ✅ User Profile & Purchase History

### Admin Panel
- ✅ Dashboard dengan Analytics
- ✅ Product Management (CRUD)
- ✅ Order Management
- ✅ User Management
- ✅ Statistik dan Laporan

### Authentication
- ✅ User Registration
- ✅ User Login
- ✅ Password Security (Bcrypt)
- ✅ Session Management

## Tech Stack

- **Language:** Node.js
- **Framework:** Express.js
- **Database:** MySQL/MariaDB dengan Sequelize ORM
- **Frontend:** EJS templates + Bootstrap 5.3 + CSS3
- **Authentication:** Session-based dengan bcrypt
- **Architecture:** MVC Pattern (Manual Implementation)

## Installation & Setup

### Prerequisites
- Node.js 16+
- MySQL/MariaDB
- npm

### Steps

1. **Install Dependencies**
   ```bash
   npm install
   ```

2. **Setup Database**
   - Import `database/schema.sql` dan `database/seeders.sql` ke MySQL
   - Atau Sequelize akan auto-sync tabel saat pertama run

3. **Run Application**
   ```bash
   npm start
   ```

4. **Access**
   - Open browser: http://localhost:3002

2. **Setup Database**
   - Buka phpMyAdmin (http://localhost/phpmyadmin)
   - Klik "Import"
   - Upload file `database/schema.sql`
   - Upload file `database/seeders.sql`

3. **Jalankan Aplikasi**
   - Akses: `http://localhost/TubesPWEB`

## User Credentials

### Admin Account
- Email: `admin@pembunuhbayaran.com`
- Password: `password` (hash it with bcrypt)
- Note: Password di database sudah di-hash

### Sample Customer
- Email: `john@example.com`
- Password: `password` (hash it dengan bcrypt)

## Folder Structure

```
TubesPWEB/
├── app/
│   ├── Controllers/     (Business Logic)
│   ├── Models/          (Database Operations)
│   └── Views/           (HTML Templates)
├── config/              (Configuration Files)
├── database/            (SQL Schema & Seeders)
├── helpers/             (Helper Functions & Database Class)
├── public/
│   ├── index.php        (Entry Point)
│   ├── css/             (Stylesheets)
│   ├── js/              (JavaScript)
│   └── images/          (Product Images)
└── .htaccess            (URL Rewriting)
```

## Routes

### Customer Routes
- `/` - Home
- `/search?q=keyword` - Search
- `/product/{slug}` - Product Detail
- `/category/{id}` - Products by Category
- `/login` - Login Page
- `/register` - Register Page
- `/logout` - Logout
- `/dashboard` - User Dashboard
- `/cart` - Shopping Cart
- `/checkout` - Checkout Page
- `/order/{id}` - Order Detail
- `/order/payment/{id}` - Payment Page
- `/wishlist` - Wishlist
- `/review/add` - Add Review
- `/cart/add` - Add to Cart
- `/cart/update` - Update Cart
- `/cart/remove` - Remove from Cart

### Admin Routes
- `/admin/dashboard` - Admin Dashboard
- `/admin/products` - List Products
- `/admin/products/create` - Create Product
- `/admin/products/{id}/edit` - Edit Product
- `/admin/products/{id}/delete` - Delete Product
- `/admin/orders` - List Orders
- `/admin/orders/{id}` - View Order
- `/admin/orders/{id}/status` - Update Order Status
- `/admin/users` - List Users
- `/admin/users/{id}` - View User
- `/admin/users/{id}/delete` - Delete User

## Payment System

Sistem pembayaran saat ini menggunakan **Dummy Payment**:
- User dapat melakukan "pembayaran" tanpa kartu kredit sebenarnya
- Cocok untuk demo dan testing
- Dapat di-upgrade ke payment gateway sebenarnya (Midtrans, Stripe, dll)

## Database Schema

### Tables
- users - User accounts
- categories - Product categories
- products - Products
- orders - Pesanan
- order_items - Detail pesanan
- cart - Shopping cart
- reviews - Product reviews
- wishlist - User wishlist
- loyalty_rewards - Loyalty points tracking

## Features Explanation

### 1. Authentication & Authorization
- User registration dengan validasi email
- Login dengan password hashing (Bcrypt)
- Session management
- Role-based access (Admin vs Customer)

### 2. Product Management
- CRUD operations untuk produk
- Categories untuk organisasi produk
- Product gambar support
- Stock management

### 3. Shopping Cart
- Add/remove/update quantity
- Persistent cart (per user)
- Real-time subtotal calculation

### 4. Order Management
- Create order dari cart
- Order tracking dengan status
- Dummy payment processing
- Email-ready (dapat di-integrate)

### 5. Loyalty Program
- Earn points dari pembelian (1 point per Rp 100,000)
- Redeem points untuk diskon
- Track points di user dashboard

### 6. Review System
- Customers dapat review produk
- Rating 1-5 stars
- Prevent duplicate reviews per user
- Display average rating

### 7. Wishlist
- Save favorite products
- Quick add to cart dari wishlist

### 8. Admin Analytics
- Total users yang terdaftar
- Total products dalam sistem
- Total orders dan revenue
- Recent orders list

## Security Notes

⚠️ **For Production Use:**
- Implement HTTPS
- Add CSRF token protection
- Sanitize all inputs dengan prepared statements (sudah ada)
- Implement rate limiting untuk login
- Add email verification untuk registration
- Secure sensitive data di database
- Use environment variables untuk database credentials

## Troubleshooting

### Error: Database connection failed
- Check database credentials di `config/config.php`
- Pastikan MySQL/MariaDB running
- Check database 'tubes_ecommerce' sudah di-create

### Error: 404 Not Found
- Check `.htaccess` di `public/` folder
- Pastikan mod_rewrite enabled di Apache
- Restart Apache

### Error: Image upload fails
- Create folder `public/images/products/`
- Check folder permissions (775)

## Performance Tips

- Add database indexes untuk frequently queried columns ✅ (sudah ada)
- Implement caching untuk product listing
- Optimize images sebelum upload
- Add pagination untuk list pages ✅ (sudah ada)

## Future Enhancements

- [ ] Email notifications untuk order
- [ ] Real payment gateway integration
- [ ] SMS notifications
- [ ] Advanced analytics & reports
- [ ] Recommendation engine
- [ ] Product variants & attributes
- [ ] Discount codes & coupons
- [ ] API endpoints untuk mobile app

## License

Ini adalah project untuk keperluan pendidikan/tugas.

## Support

Jika ada pertanyaan atau issues, silakan create issue atau contact developer.

---

**Created:** April 2026
**Status:** Complete & Ready for Deployment
