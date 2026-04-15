const http = require('http');
const querystring = require('querystring');

function post(path, data, cookie) {
  const body = querystring.stringify(data);
  const headers = {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': Buffer.byteLength(body)
  };
  if (cookie) headers.Cookie = cookie;

  return new Promise((resolve, reject) => {
    const req = http.request({ hostname:'127.0.0.1', port:3003, path, method:'POST', headers }, res => {
      let data = '';
      res.on('data', chunk => data += chunk);
      res.on('end', () => resolve({ res, body: data }));
    });
    req.on('error', reject);
    req.write(body);
    req.end();
  });
}

(async () => {
  try {
    const login = await post('/auth/login', { email: 'checkoutuser123@example.com', password: 'pass1234' });
    console.log('login status', login.res.statusCode);
    console.log('login location', login.res.headers.location);
    const cookie = login.res.headers['set-cookie'] ? login.res.headers['set-cookie'].map(c => c.split(';')[0]).join('; ') : '';
    console.log('cookie', cookie);
    const review = await post('/review/add/1', { rating: 5, comment: 'Test review' }, cookie);
    console.log('review status', review.res.statusCode);
    console.log('review headers', review.res.headers);
    console.log('review body', review.body);
  } catch (err) {
    console.error(err);
  }
})();
