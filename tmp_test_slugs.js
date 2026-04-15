const http = require('http');
const slugs = [
  'adidas-jacket','body-guard-elite-assassin','g2-combat-a1-pistol','g2-elite-pistol','g2-premium-pistol',
  'hardcover-novel','iphone-15-pro','macbook-air-m3','mag-4-pistol','mo-1-mortar','mo-2-mortar','mo-3-mortar',
  'nike-running-shoes','p3a-pistol','paket-bebas-hukum-vip','paket-cleanup-tkp-professional','paket-polisi-damai-premium',
  'premium-coffee','samsung-galaxy-s24','sar-2-grenade-launcher','smart-watch','sony-headphones','spg1a-v2-grenade-launcher',
  'spg1a-v3-grenade-launcher','spg1a-v4-grenade-launcher','ss2-v1-assault-rifle','ss2-v2-assault-rifle','ss2-v3-assault-rifle',
  'ss2-v4-assault-rifle','ss2-v5-assault-rifle','usb-c-cable','wooden-shelf','yoga-mat'
];

(async () => {
  for (const slug of slugs) {
    try {
      const res = await new Promise((resolve, reject) => {
        const req = http.request({ host:'127.0.0.1', port: 3003, path:`/product/${slug}`, method:'GET' }, resolve);
        req.on('error', reject);
        req.end();
      });
      console.log(slug, res.statusCode);
    } catch (err) {
      console.error(slug, 'ERROR', err.message);
    }
  }
})();
