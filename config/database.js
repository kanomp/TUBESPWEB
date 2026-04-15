const { Sequelize } = require('sequelize');

const sequelize = new Sequelize('tubes_ecommerce', 'root', '1234', {
  host: 'localhost',
  dialect: 'mysql',
  logging: false
});

module.exports = sequelize; 