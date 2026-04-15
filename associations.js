const Product = require('./models/Product');
const Review = require('./models/Review');
const User = require('./models/User');
const Category = require('./models/Category');
const Cart = require('./models/Cart');
const Order = require('./models/Order');
const OrderItem = require('./models/OrderItem');
const Wishlist = require('./models/Wishlist');

// Define associations
Product.belongsTo(Category, { foreignKey: 'category_id', as: 'category' });
Product.hasMany(Review, { foreignKey: 'product_id', as: 'reviews' });

Review.belongsTo(User, { foreignKey: 'user_id', as: 'user' });
Review.belongsTo(Product, { foreignKey: 'product_id', as: 'product' });

User.hasMany(Review, { foreignKey: 'user_id', as: 'reviews' });
User.hasMany(Cart, { foreignKey: 'user_id', as: 'carts' });
User.hasMany(Order, { foreignKey: 'user_id', as: 'orders' });
User.hasMany(Wishlist, { foreignKey: 'user_id', as: 'wishlists' });

Cart.belongsTo(User, { foreignKey: 'user_id', as: 'cartUser' });
Cart.belongsTo(Product, { foreignKey: 'product_id', as: 'cartProduct' });

Order.belongsTo(User, { foreignKey: 'user_id', as: 'user' });
Order.hasMany(OrderItem, { foreignKey: 'order_id', as: 'orderItems' });

OrderItem.belongsTo(Order, { foreignKey: 'order_id', as: 'order' });
OrderItem.belongsTo(Product, { foreignKey: 'product_id', as: 'itemProduct' });

Wishlist.belongsTo(User, { foreignKey: 'user_id', as: 'wishUser' });
Wishlist.belongsTo(Product, { foreignKey: 'product_id', as: 'wishProduct' });

Category.hasMany(Product, { foreignKey: 'category_id', as: 'products' });