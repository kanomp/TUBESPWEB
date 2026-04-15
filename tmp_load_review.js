try {
  require('./routes/review');
  console.log('ok');
} catch (err) {
  console.error(err);
  process.exit(1);
}
