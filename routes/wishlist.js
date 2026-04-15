const express = require('express');
const router = express.Router();
const { requireAuth } = require('../middleware/auth');
const Wishlist = require('../models/Wishlist');
const Product = require('../models/Product');

// View wishlist
router.get('/', requireAuth, async (req, res) => {
  try {
    const wishlistItems = await Wishlist.findAll({
      where: { user_id: req.session.user.id },
      include: [{ model: Product, as: 'wishProduct' }],
      order: [['created_at', 'DESC']]
    });

    res.render('wishlist/index', {
      title: 'Wishlist',
      layout: 'layouts/main',
      wishlistItems,
      user: req.session.user
    });
  } catch (error) {
    console.error(error);
    res.status(500).send('Server Error');
  }
});

// Add to wishlist
router.post('/add/:productId', requireAuth, async (req, res) => {
  try {
    const productId = req.params.productId;
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;
    const referer = req.get('referer') || '/wishlist';

    // Check if already in wishlist
    const existing = await Wishlist.findOne({
      where: { user_id: req.session.user.id, product_id: productId }
    });

    if (existing) {
      if (wantsJSON) {
        return res.json({ success: false, message: 'Product already in wishlist' });
      }
      return res.redirect(referer);
    }

    await Wishlist.create({
      user_id: req.session.user.id,
      product_id: productId
    });

    if (wantsJSON) {
      return res.json({ success: true, message: 'Product added to wishlist' });
    }

    res.redirect(referer);
  } catch (error) {
    console.error(error);
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;
    if (wantsJSON) {
      return res.status(500).json({ error: 'Server error' });
    }
    res.redirect(req.get('referer') || '/wishlist');
  }
});

// Remove from wishlist
router.post('/remove/:productId', requireAuth, async (req, res) => {
  try {
    const productId = req.params.productId;
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;
    const referer = req.get('referer') || '/wishlist';

    await Wishlist.destroy({
      where: { user_id: req.session.user.id, product_id: productId }
    });

    if (wantsJSON) {
      return res.json({ success: true, message: 'Product removed from wishlist' });
    }

    res.redirect(referer);
  } catch (error) {
    console.error(error);
    const wantsJSON = req.get('x-requested-with') === 'XMLHttpRequest' || 
                      req.get('accept')?.includes('application/json') === true;
    if (wantsJSON) {
      return res.status(500).json({ error: 'Server error' });
    }
    res.redirect(req.get('referer') || '/wishlist');
  }
});

module.exports = router;