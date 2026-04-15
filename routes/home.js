const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const { Op } = require('sequelize');
const sequelize = require('../config/database');
const { requireAuth } = require('../middleware/auth');
const Product = require('../models/Product');
const Category = require('../models/Category');
const Review = require('../models/Review');
const User = require('../models/User');
const Cart = require('../models/Cart');
const Order = require('../models/Order');
const OrderItem = require('../models/OrderItem');

// Middleware to get cart count
const getCartCount = async (req, res, next) => {
  if (req.session.user) {
    try {
      const cartCount = await Cart.sum('quantity', {
        where: { user_id: req.session.user.id }
      });
      req.cartCount = cartCount || 0;
    } catch (error) {
      req.cartCount = 0;
    }
  } else {
    req.cartCount = 0;
  }
  next();
};

// Apply cart count middleware to all routes
router.use(getCartCount);

// Home page
router.get('/', async (req, res) => {
  try {
    const page = parseInt(req.query.page) || 1;
    const limit = 12;
    const offset = (page - 1) * limit;

    const { count, rows: products } = await Product.findAndCountAll({
      where: { is_active: true },
      include: [{ model: Category, as: 'category' }],
      limit,
      offset,
      order: [['created_at', 'DESC']]
    });

    const categories = await Category.findAll();
    const totalPages = Math.ceil(count / limit);

    res.render('home/index', {
      title: 'Home',
      layout: 'layouts/main',
      products,
      categories,
      currentPage: page,
      totalPages,
      user: req.session.user,
      cartCount: req.cartCount
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Search products
router.get('/search', async (req, res) => {
  try {
    const query = req.query.q || '';
    const page = parseInt(req.query.page) || 1;
    const limit = 12;
    const offset = (page - 1) * limit;

    const { count, rows: products } = await Product.findAndCountAll({
      where: {
        is_active: true,
        [Op.or]: [
          { name: { [Op.like]: `%${query}%` } },
          { description: { [Op.like]: `%${query}%` } }
        ]
      },
      include: [{ model: Category, as: 'category' }],
      limit,
      offset,
      order: [['created_at', 'DESC']]
    });

    const categories = await Category.findAll();
    const totalPages = Math.ceil(count / limit);

    res.render('home/search', {
      title: 'Search Results',
      layout: 'layouts/main',
      products,
      categories,
      query,
      currentPage: page,
      totalPages,
      user: req.session.user,
      cartCount: req.cartCount
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Product detail
router.get('/product/:slug', async (req, res) => {
  try {
    const product = await Product.findOne({
      where: { slug: req.params.slug, is_active: true },
      include: [
        { model: Category, as: 'category' },
        { model: Review, as: 'reviews', include: [{ model: User, as: 'user' }] }
      ]
    });

    if (!product) {
      return res.status(404).render('404');
    }

    // Calculate average rating and total reviews
    const reviewStats = await Review.findAll({
      where: { product_id: product.id },
      attributes: [
        [sequelize.fn('AVG', sequelize.col('rating')), 'avgRating'],
        [sequelize.fn('COUNT', sequelize.col('id')), 'totalReviews']
      ],
      raw: true
    });

    product.avgRating = parseFloat(reviewStats[0].avgRating) || 0;
    product.totalReviews = parseInt(reviewStats[0].totalReviews) || 0;

    let canReview = false;
    let hasReviewed = false;
    let reviewMessage = null;

    if (req.session.user) {
      const review = await Review.findOne({
        where: { user_id: req.session.user.id, product_id: product.id }
      });

      hasReviewed = !!review;

      const purchasedOrder = await OrderItem.findOne({
        include: [{
          model: Order,
          as: 'order',
          where: {
            user_id: req.session.user.id,
            payment_status: 'paid'
          }
        }],
        where: { product_id: product.id }
      });

      canReview = !!purchasedOrder;

      if (!canReview) {
        reviewMessage = 'Review hanya dapat ditambahkan setelah produk dibayar.';
      } else if (hasReviewed) {
        reviewMessage = 'Anda sudah memberikan review untuk produk ini.';
      }
    }

    res.render('home/detail', {
      title: product.name,
      layout: 'layouts/main',
      product,
      user: req.session.user,
      cartCount: req.cartCount,
      canReview,
      hasReviewed,
      reviewMessage
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Category page
router.get('/category/:id', async (req, res) => {
  try {
    const categoryId = req.params.id;
    const page = parseInt(req.query.page) || 1;
    const limit = 12;
    const offset = (page - 1) * limit;

    const category = await Category.findByPk(categoryId);
    if (!category) {
      return res.status(404).render('404');
    }

    const { count, rows: products } = await Product.findAndCountAll({
      where: { category_id: categoryId, is_active: true },
      include: [{ model: Category, as: 'category' }],
      limit,
      offset,
      order: [['created_at', 'DESC']]
    });

    const categories = await Category.findAll();
    const totalPages = Math.ceil(count / limit);

    res.render('home/category', {
      title: category.name,
      layout: 'layouts/main',
      products,
      category,
      categories,
      currentPage: page,
      totalPages,
      user: req.session.user,
      cartCount: req.cartCount
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// User Dashboard
router.get('/dashboard', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    
    // Get user data
    const user = await User.findByPk(userId);
    
    // Get user's recent orders
    const orders = await Order.findAll({
      where: { user_id: userId },
      order: [['created_at', 'DESC']],
      limit: 5
    });
    
    // Get user's wishlist
    const Wishlist = require('../models/Wishlist');
    const wishlistCount = await Wishlist.count({ where: { user_id: userId } });
    
    res.render('home/dashboard', {
      title: 'My Dashboard',
      layout: 'layouts/main',
      user: req.session.user,
      cartCount: req.cartCount,
      userData: user,
      orders: orders,
      wishlistCount: wishlistCount
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// User Profile
router.get('/profile', requireAuth, async (req, res) => {
  try {
    const userId = req.session.user.id;
    
    // Get user data
    const user = await User.findByPk(userId);
    
    res.render('home/profile', {
      title: 'My Profile',
      layout: 'layouts/main',
      user: req.session.user,
      cartCount: req.cartCount,
      userData: user
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// About Page
router.get('/about', async (req, res) => {
  try {
    res.render('home/about', {
      title: 'About Us',
      layout: 'layouts/main',
      user: req.session.user || null,
      cartCount: req.cartCount || 0
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Update Profile (Change Name)
router.post('/profile/update', requireAuth, async (req, res) => {
  try {
    const { name } = req.body;
    const userId = req.session.user.id;

    if (!name || name.trim() === '') {
      return res.status(400).json({ success: false, message: 'Nama tidak boleh kosong' });
    }

    // Update user in database
    await User.update({ name: name.trim() }, { where: { id: userId } });

    // Update session
    req.session.user.name = name.trim();

    res.json({ success: true, message: 'Nama berhasil diperbarui' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Gagal memperbarui nama' });
  }
});

// Change Password
router.post('/profile/change-password', requireAuth, async (req, res) => {
  try {
    const { current_password, new_password, confirm_password } = req.body;
    const userId = req.session.user.id;

    // Validate inputs
    if (!current_password || !new_password || !confirm_password) {
      return res.status(400).json({ success: false, message: 'Semua field harus diisi' });
    }

    if (new_password.length < 8) {
      return res.status(400).json({ success: false, message: 'Password baru minimal 8 karakter' });
    }

    if (new_password !== confirm_password) {
      return res.status(400).json({ success: false, message: 'Password baru dan konfirmasi tidak cocok' });
    }

    // Get user from database
    const user = await User.findByPk(userId);

    if (!user) {
      return res.status(404).json({ success: false, message: 'User tidak ditemukan' });
    }

    // Verify current password
    const isPasswordValid = await bcrypt.compare(current_password, user.password);

    if (!isPasswordValid) {
      return res.status(401).json({ success: false, message: 'Password saat ini salah' });
    }

    // Hash new password
    const hashedPassword = await bcrypt.hash(new_password, 12);

    // Update password in database
    await User.update({ password: hashedPassword }, { where: { id: userId } });

    res.json({ success: true, message: 'Password berhasil diubah' });
  } catch (error) {
    console.error(error);
    res.status(500).json({ success: false, message: 'Gagal mengubah password' });
  }
});

module.exports = router;