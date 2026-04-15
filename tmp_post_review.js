const http = require('http');
const querystring = require('querystring');
const data = querystring.stringify({ rating: 5, comment: 'Test review' });

const options = {
  hostname: '127.0.0.1',
  port: 3003,
  path: '/review/add/1',
  method: 'POST',
  headers: {
    'Content-Type': 'application/x-www-form-urlencoded',
    'Content-Length': Buffer.byteLength(data),
    'Cookie': 'connect.sid=s%3Ab7b4w4UN1v3fc75LmdgqnO0z-z9PNA89.jCOtc%2FIGwCzCobD%2BiOmorAroLX0SYG%2Bo%2BhAi7CzA5ig'
  }
};

const req = http.request(options, res => {
  console.log('STATUS', res.statusCode);
  console.log('HEADERS', res.headers);
  res.setEncoding('utf8');
  let body = '';
  res.on('data', chunk => body += chunk);
  res.on('end', () => {
    console.log('BODY');
    console.log(body);
  });
});
req.on('error', err => console.error('ERROR', err));
req.write(data);
req.end();
