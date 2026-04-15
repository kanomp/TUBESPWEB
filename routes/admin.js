const express = require('express');
const router = express.Router();
const bcrypt = require('bcrypt');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const { requireAdmin } = require('../middleware/auth');
const { Op } = require('sequelize');
const User = require('../models/User');
const Product = require('../models/Product');
const Order = require('../models/Order');
const OrderItem = require('../models/OrderItem');
const Cart = require('../models/Cart');
const Category = require('../models/Category');

// Setup multer for file upload
const uploadDir = path.join(__dirname, '../public/images/Produk/');
if (!fs.existsSync(uploadDir)) {
  fs.mkdirSync(uploadDir, { recursive: true });
}

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    cb(null, uploadDir);
  },
  filename: (req, file, cb) => {
    const uniqueSuffix = Date.now() + '-' + Math.round(Math.random() * 1E9);
    cb(null, 'product-' + uniqueSuffix + path.extname(file.originalname));
  }
});

const upload = multer({
  storage: storage,
  fileFilter: (req, file, cb) => {
    const allowedTypes = /jpeg|jpg|png|gif/;
    const extname = allowedTypes.test(path.extname(file.originalname).toLowerCase());
    const mimetype = allowedTypes.test(file.mimetype);
    
    if (mimetype && extname) {
      return cb(null, true);
    } else {
      cb(new Error('Hanya file gambar (jpeg, jpg, png, gif) yang diizinkan'));
    }
  }
});

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

// Apply cart count middleware to all admin routes
router.use(getCartCount);

router.get('/dashboard', requireAdmin, async (req, res) => {
  try {
    // Get statistics
    const totalUsers = await User.count();
    const totalProducts = await Product.count();
    const totalOrders = await Order.count();
    
    // Calculate revenue
    const revenueResult = await Order.sum('total_amount');
    const revenue = revenueResult || 0;
    
    // Get recent orders
    const recentOrders = await Order.findAll({
      include: [{ model: User, as: 'user' }],
      order: [['created_at', 'DESC']],
      limit: 5
    });

    res.render('admin/dashboard', {
      title: 'Admin Dashboard',
      layout: 'layouts/main',
      user: req.session.user,
      cartCount: req.cartCount || 0,
      stats: {
        totalUsers,
        totalProducts,
        totalOrders,
        revenue
      },
      recentOrders
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// List all products
router.get('/products', requireAdmin, async (req, res) => {
  try {
    const products = await Product.findAll({
      order: [['created_at', 'DESC']]
    });

    res.render('admin/products', {
      title: 'Manage Products',
      layout: 'layouts/main',
      user: req.session.user,
      products,
      cartCount: req.cartCount || 0
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Show create product form
router.get('/products/create', requireAdmin, async (req, res) => {
  try {
    const categories = await Category.findAll();
    res.render('admin/products/create', {
      title: 'Add Product',
      layout: 'layouts/main',
      user: req.session.user,
      categories,
      cartCount: req.cartCount || 0
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Store new product
router.post('/products/store', requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const { name, description, price, stock, category_id } = req.body;
    
    if (!name || !price || !category_id) {
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(400).send('Name, price, and category are required');
    }

    // Generate slug from name
    const slug = name.toLowerCase().replace(/[^a-z0-9]+/g, '-').replace(/(^-|-$)/g, '');

    const imageName = req.file ? req.file.filename : null;

    const product = await Product.create({
      name,
      slug,
      description,
      price,
      stock: parseInt(stock) || 0,
      category_id: parseInt(category_id),
      image: imageName,
      is_active: true
    });

    res.redirect(`/admin/products/view/${product.id}`);
  } catch (error) {
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    console.error(error);
    res.status(500).send('Server Error: ' + error.message);
  }
});

// List all orders
router.get('/orders', requireAdmin, async (req, res) => {
  try {
    const orders = await Order.findAll({
      include: [{ model: User, as: 'user' }],
      order: [['created_at', 'DESC']]
    });

    res.render('admin/orders', {
      title: 'Manage Orders',
      layout: 'layouts/main',
      user: req.session.user,
      orders,
      cartCount: req.cartCount || 0
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// List all users
router.get('/users', requireAdmin, async (req, res) => {
  try {
    const users = await User.findAll({
      order: [['created_at', 'DESC']]
    });

    res.render('admin/users', {
      title: 'Manage Users',
      layout: 'layouts/main',
      user: req.session.user,
      users,
      cartCount: req.cartCount || 0
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// View user detail
router.get('/users/view/:id', requireAdmin, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);

    if (!user) {
      return res.status(404).send('User not found');
    }

    res.render('admin/users/view', {
      title: 'User Detail',
      layout: 'layouts/main',
      user: req.session.user,
      managedUser: user,
      cartCount: req.cartCount || 0
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Show edit user form
router.get('/users/edit/:id', requireAdmin, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);

    if (!user) {
      return res.status(404).send('User not found');
    }

    res.render('admin/users/edit', {
      title: 'Edit User',
      layout: 'layouts/main',
      user: req.session.user,
      managedUser: user,
      cartCount: req.cartCount || 0
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Update user
router.post('/users/update/:id', requireAdmin, async (req, res) => {
  try {
    const { name, email, phone, address, role, password } = req.body;
    const user = await User.findByPk(req.params.id);

    if (!user) {
      return res.status(404).send('User not found');
    }

    user.name = name;
    user.email = email;
    user.phone = phone;
    user.address = address;
    user.role = role;

    if (password && password.trim().length > 0) {
      user.password = await bcrypt.hash(password, 12);
    }

    await user.save();

    res.redirect(`/admin/users/view/${user.id}`);
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Delete user
router.post('/users/delete/:id', requireAdmin, async (req, res) => {
  try {
    const user = await User.findByPk(req.params.id);

    if (!user) {
      return res.status(404).send('User not found');
    }

    if (req.session.user.id === user.id) {
      return res.status(400).send('You cannot delete your own admin account.');
    }

    await user.destroy();
    res.redirect('/admin/users');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

router.get('/orders/view/:id', requireAdmin, async (req, res) => {
  try {
    const order = await Order.findOne({
      where: { id: req.params.id },
      include: [
        { model: User, as: 'user' },
        { model: OrderItem, as: 'orderItems', include: [{ model: Product, as: 'itemProduct' }] }
      ]
    });

    if (!order) {
      return res.status(404).send('Order not found');
    }

    res.render('admin/orders/view', {
      title: 'Order Detail',
      layout: 'layouts/main',
      order,
      user: req.session.user
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

router.post('/orders/update-status/:id', requireAdmin, async (req, res) => {
  try {
    const { status } = req.body;
    const order = await Order.findByPk(req.params.id);

    if (!order) {
      return res.status(404).send('Order not found');
    }

    order.status = status;
    await order.save();

    res.redirect(`/admin/orders/view/${order.id}`);
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// View product detail
router.get('/products/view/:id', requireAdmin, async (req, res) => {
  try {
    const product = await Product.findByPk(req.params.id);

    if (!product) {
      return res.status(404).send('Product not found');
    }

    res.render('admin/products/view', {
      title: 'Product Detail',
      layout: 'layouts/main',
      user: req.session.user,
      product,
      cartCount: req.cartCount || 0
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Show edit form
router.get('/products/edit/:id', requireAdmin, async (req, res) => {
  try {
    const product = await Product.findByPk(req.params.id);

    if (!product) {
      return res.status(404).send('Product not found');
    }

    res.render('admin/products/edit', {
      title: 'Edit Product',
      layout: 'layouts/main',
      user: req.session.user,
      product,
      cartCount: req.cartCount || 0
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Update product
router.post('/products/update/:id', requireAdmin, upload.single('image'), async (req, res) => {
  try {
    const { name, description, price, stock, category_id } = req.body;
    const product = await Product.findByPk(req.params.id);

    if (!product) {
      if (req.file) {
        fs.unlinkSync(req.file.path);
      }
      return res.status(404).send('Product not found');
    }

    product.name = name;
    product.description = description;
    product.price = price;
    product.stock = stock;
    product.category_id = category_id;

    // Handle image upload
    if (req.file) {
      // Delete old image if exists
      if (product.image) {
        const oldImagePath = path.join(uploadDir, product.image);
        if (fs.existsSync(oldImagePath)) {
          fs.unlinkSync(oldImagePath);
        }
      }
      product.image = req.file.filename;
    }

    await product.save();

    res.redirect(`/admin/products/view/${product.id}`);
  } catch (error) {
    if (req.file) {
      fs.unlinkSync(req.file.path);
    }
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Delete product
router.post('/products/delete/:id', requireAdmin, async (req, res) => {
  try {
    const product = await Product.findByPk(req.params.id);

    if (!product) {
      return res.status(404).send('Product not found');
    }

    await product.destroy();
    res.redirect('/admin/products');
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

module.exports = router;