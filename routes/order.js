const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const Cart = require('../models/Cart');
const Order = require('../models/Order');
const OrderItem = require('../models/OrderItem');
const Product = require('../models/Product');
const User = require('../models/User');

// Checkout page
router.get('/checkout', requireAuth, async (req, res) => {
  try {
    const cartItems = await Cart.findAll({
      where: { user_id: req.session.user.id },
      include: [{ model: Product, as: 'cartProduct' }]
    });

    if (cartItems.length === 0) {
      return res.redirect('/cart');
    }

    const total = cartItems.reduce((sum, item) => {
      return sum + (parseFloat(item.cartProduct.price) * item.quantity);
    }, 0);

    res.render('order/checkout', {
      title: 'Checkout',
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

// Process checkout
router.post('/checkout', requireAuth, async (req, res) => {
  try {
    const { shipping_address, phone } = req.body;

    const cartItems = await Cart.findAll({
      where: { user_id: req.session.user.id },
      include: [{ model: Product, as: 'cartProduct' }]
    });

    if (cartItems.length === 0) {
      return res.redirect('/cart');
    }

    // Calculate total
    const total = cartItems.reduce((sum, item) => {
      return sum + (parseFloat(item.cartProduct.price) * item.quantity);
    }, 0);

    const shippingAddress = shipping_address?.trim() || req.session.user.address || '';

    if (phone && phone.trim()) {
      await User.update({ phone: phone.trim() }, { where: { id: req.session.user.id } });
      req.session.user.phone = phone.trim();
    }

    if (shippingAddress) {
      await User.update({ address: shippingAddress }, { where: { id: req.session.user.id } });
      req.session.user.address = shippingAddress;
    }

    // Generate order number
    const orderNumber = 'ORD' + Date.now() + Math.random().toString(36).substr(2, 5).toUpperCase();

    // Create order
    const order = await Order.create({
      order_number: orderNumber,
      user_id: req.session.user.id,
      total_amount: total,
      shipping_address: shippingAddress,
      status: 'pending'
    });

    // Create order items and update stock
    for (const item of cartItems) {
      await OrderItem.create({
        order_id: order.id,
        product_id: item.product_id,
        quantity: item.quantity,
        price: item.cartProduct.price
      });

      // Update product stock
      item.cartProduct.stock -= item.quantity;
      await item.cartProduct.save();
    }

    // Clear cart
    await Cart.destroy({ where: { user_id: req.session.user.id } });

    res.redirect(`/order/payment/${order.id}`);
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Payment page
router.get('/payment/:id', requireAuth, async (req, res) => {
  try {
    const order = await Order.findOne({
      where: { id: req.params.id, user_id: req.session.user.id },
      include: [{ model: OrderItem, as: 'orderItems', include: [{ model: Product, as: 'itemProduct' }] }]
    });

    if (!order) {
      return res.status(404).send('Order not found');
    }

    res.render('order/payment', {
      title: 'Payment',
      layout: 'layouts/main',
      order,
      user: req.session.user
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Process payment (dummy)
router.post('/payment/:id', requireAuth, async (req, res) => {
  try {
    const order = await Order.findOne({
      where: { id: req.params.id, user_id: req.session.user.id }
    });

    if (!order) {
      return res.status(404).send('Order not found');
    }

    // Dummy payment processing
    order.status = 'processing';
    order.payment_status = 'paid';
    await order.save();

    res.redirect(`/order/detail/${order.id}`);
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Order detail
router.get('/detail/:id', requireAuth, async (req, res) => {
  try {
    const order = await Order.findOne({
      where: { id: req.params.id, user_id: req.session.user.id },
      include: [{ model: OrderItem, as: 'orderItems', include: [{ model: Product, as: 'itemProduct' }] }]
    });

    if (!order) {
      return res.status(404).send('Order not found');
    }

    res.render('order/detail', {
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

module.exports = router;