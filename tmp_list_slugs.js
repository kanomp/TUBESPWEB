const Product = require('./models/Product');
const sequelize = require('./config/database');

(async () => {
  try {
    await sequelize.authenticate();
    const prods = await Product.findAll({ attributes: ['slug'], limit: 50 });
    prods.forEach(p => console.log(p.slug));
  } catch (err) {
    console.error(err);
  } finally {
    process.exit();
  }
})();
