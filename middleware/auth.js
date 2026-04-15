// Middleware to check if user is logged in
const requireAuth = (req, res, next) => {
  if (!req.session.user) {
    // Check if this is an AJAX request
    if (req.headers['x-requested-with'] === 'XMLHttpRequest' || req.headers.accept?.includes('application/json')) {
      return res.status(401).json({ success: false, message: 'Sesi Anda telah berakhir. Silakan login kembali.' });
    }
    return res.redirect('/auth/login');
  }
  next();
};

// Middleware to check if user is admin
const requireAdmin = (req, res, next) => {
  if (!req.session.user || req.session.user.role !== 'admin') {
    // Check if this is an AJAX request
    if (req.headers['x-requested-with'] === 'XMLHttpRequest' || req.headers.accept?.includes('application/json')) {
      return res.status(403).json({ success: false, message: 'Akses ditolak. Anda tidak memiliki izin admin.' });
    }
    return res.status(403).send('Access denied');
  }
  next();
};

module.exports = {
  requireAuth,
  requireAdmin
};