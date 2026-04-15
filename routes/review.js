const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const { Op } = require('sequelize');
const Review = require('../models/Review');
const Product = require('../models/Product');
const Order = require('../models/Order');
const OrderItem = require('../models/OrderItem');

// Add review
router.post('/add/:productId', requireAuth, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const productId = req.params.productId;
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;

    const product = await Product.findByPk(productId);
    const defaultRedirect = product ? `/product/${product.slug}` : '/';
    const referer = req.get('referer') || defaultRedirect;

    if (!product) {
      if (wantsJSON) {
        return res.status(404).json({ error: 'Product not found' });
      }
      return res.redirect(defaultRedirect);
    }

    // Check if user has purchased this product and completed payment
    const hasPurchased = await OrderItem.findOne({
      include: [{
        model: Order,
        as: 'order',
        where: {
          user_id: req.session.user.id,
          payment_status: 'paid',
          status: { [Op.not]: 'cancelled' }
        }
      }],
      where: { product_id: productId }
    });

    if (!hasPurchased) {
      if (wantsJSON) {
        return res.status(403).json({ error: 'You can only review products you have purchased' });
      }
      return res.redirect(referer);
    }

    // Check if already reviewed
    const existingReview = await Review.findOne({
      where: { user_id: req.session.user.id, product_id: productId }
    });

    if (existingReview) {
      if (wantsJSON) {
        return res.status(400).json({ error: 'You have already reviewed this product' });
      }
      return res.redirect(referer);
    }

    await Review.create({
      user_id: req.session.user.id,
      product_id: productId,
      rating: parseInt(rating),
      comment
    });

    if (wantsJSON) {
      return res.json({ success: true, message: 'Review added successfully' });
    }

    res.redirect(referer);
  } catch (error) {
    console.error(error);
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;
    if (wantsJSON) {
      return res.status(500).json({ error: 'Server error' });
    }
    const product = await Product.findByPk(req.params.productId);
    const defaultRedirect = product ? `/product/${product.slug}` : '/';
    res.redirect(req.get('referer') || defaultRedirect);
  }
});

// Update review
router.post('/update/:productId', requireAuth, async (req, res) => {
  try {
    const { rating, comment } = req.body;
    const productId = req.params.productId;
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;

    const product = await Product.findByPk(productId);
    const defaultRedirect = product ? `/product/${product.slug}` : '/';
    const referer = req.get('referer') || defaultRedirect;

    const review = await Review.findOne({
      where: { user_id: req.session.user.id, product_id: productId }
    });

    if (!review) {
      if (wantsJSON) {
        return res.status(404).json({ error: 'Review not found' });
      }
      return res.redirect(referer);
    }

    review.rating = parseInt(rating);
    review.comment = comment;
    await review.save();

    if (wantsJSON) {
      return res.json({ success: true, message: 'Review updated successfully' });
    }

    res.redirect(referer);
  } catch (error) {
    console.error(error);
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;
    if (wantsJSON) {
      return res.status(500).json({ error: 'Server error' });
    }
    const product = await Product.findByPk(req.params.productId);
    const defaultRedirect = product ? `/product/${product.slug}` : '/';
    res.redirect(req.get('referer') || defaultRedirect);
  }
});

module.exports = router;