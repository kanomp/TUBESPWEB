const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const Cart = require('../models/Cart');
const Product = require('../models/Product');

// View cart
router.get('/', requireAuth, async (req, res) => {
  try {
    const cartItems = await Cart.findAll({
      where: { user_id: req.session.user.id },
      include: [{ model: Product, as: 'cartProduct' }],
      order: [['created_at', 'DESC']]
    });

    const total = cartItems.reduce((sum, item) => {
      return sum + (parseFloat(item.cartProduct.price) * item.quantity);
    }, 0);

    res.render('cart/index', {
      title: 'Shopping Cart',
      layout: 'layouts/main',
      cartItems,
      total,
      user: req.session.user
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Add to cart
router.post('/add', requireAuth, async (req, res) => {
  try {
    const { product_id, quantity = 1 } = req.body;
    const referer = req.get('referer') || '/cart';
    // Only return JSON if explicitly requested via AJAX or API header
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;

    const product = await Product.findByPk(product_id);
    if (!product || !product.is_active) {
      if (wantsJSON) {
        return res.status(404).json({ error: 'Product not found' });
      }
      return res.redirect(referer);
    }

    if (product.stock < quantity) {
      if (wantsJSON) {
        return res.status(400).json({ error: 'Insufficient stock' });
      }
      return res.redirect(referer);
    }

    // Check if item already in cart
    const existingItem = await Cart.findOne({
      where: { user_id: req.session.user.id, product_id }
    });

    if (existingItem) {
      const newQuantity = existingItem.quantity + parseInt(quantity);
      if (newQuantity > product.stock) {
        if (wantsJSON) {
          return res.status(400).json({ error: 'Insufficient stock' });
        }
        return res.redirect(referer);
      }
      existingItem.quantity = newQuantity;
      await existingItem.save();
    } else {
      await Cart.create({
        user_id: req.session.user.id,
        product_id,
        quantity: parseInt(quantity)
      });
    }

    if (wantsJSON) {
      return res.json({ success: true, message: 'Product added to cart' });
    }

    res.redirect('/cart');
  } catch (error) {
    console.error(error);
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;
    if (wantsJSON) {
      return res.status(500).json({ error: 'Server error' });
    }
    res.redirect(req.get('referer') || '/cart');
  }
});

// Update cart quantity
router.post('/update/:id', requireAuth, async (req, res) => {
  try {
    const { quantity } = req.body;
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;
    const referer = req.get('referer') || '/cart';

    const cartItem = await Cart.findOne({
      where: { id: req.params.id, user_id: req.session.user.id },
      include: [{ model: Product, as: 'cartProduct' }]
    });

    if (!cartItem) {
      if (wantsJSON) {
        return res.status(404).json({ error: 'Cart item not found' });
      }
      return res.redirect(referer);
    }

    if (quantity <= 0) {
      await cartItem.destroy();
    } else if (quantity > cartItem.cartProduct.stock) {
      if (wantsJSON) {
        return res.status(400).json({ error: 'Insufficient stock' });
      }
      return res.redirect(referer);
    } else {
      cartItem.quantity = quantity;
      await cartItem.save();
    }

    if (wantsJSON) {
      return res.json({ success: true });
    }

    res.redirect(referer);
  } catch (error) {
    console.error(error);
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;
    if (wantsJSON) {
      return res.status(500).json({ error: 'Server error' });
    }
    res.redirect(req.get('referer') || '/cart');
  }
});

// Remove from cart
router.post('/remove/:id', requireAuth, async (req, res) => {
  try {
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;
    const referer = req.get('referer') || '/cart';

    const cartItem = await Cart.findOne({
      where: { id: req.params.id, user_id: req.session.user.id }
    });

    if (!cartItem) {
      if (wantsJSON) {
        return res.status(404).json({ error: 'Cart item not found' });
      }
      return res.redirect(referer);
    }

    await cartItem.destroy();

    if (wantsJSON) {
      return res.json({ success: true });
    }

    res.redirect(referer);
  } catch (error) {
    console.error(error);
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;
    if (wantsJSON) {
      return res.status(500).json({ error: 'Server error' });
    }
    res.redirect(req.get('referer') || '/cart');
  }
});

module.exports = router;