const express = require('express');
const router = express.Router();
const escape = require('escape-html');

const createDOMPurify = require('dompurify');
const { JSDOM } = require('jsdom');

/* GET home page. */
router.get('/', function(req, res, next) {
  res.clearCookie('expiration');
  res.render('index', {
    title: 'Express'
  });
});

router.post('/data-vuln', function(req, res, next) {
  const body = req.body;
  res.clearCookie('expiration');

  if (body.isVulnerable) {
    // add a day to the cookie
    res.cookie('expiration', new Date(Date.now() + 86400000));
  } else {
    // encrypt the cookie so no one can change it
    res.cookie('expiration', new Date(Date.now() + 86400000), {
      signed: true,
      httpOnly: true
    });
  }

  // go to countdown route with vuln param
  res.redirect(`/countdown?vuln=${body.isVulnerable ? 1 : 0}`);
});

router.get('/countdown', function (req, res, next) {
  const vuln = Boolean(req.query.vuln === '1');
  console.log('vuln', vuln)

  console.log('signed cookie', req.signedCookies, 'exp:', req.signedCookies.expiration );

  const expiration = vuln === true ? req.cookies.expiration : req.signedCookies.expiration;
  console.log('expiration', expiration);

  const now = new Date();
  const diff = new Date(expiration) - now;
  const days = Math.floor(diff / 1000 / 60 / 60 / 24);
  const hours = Math.floor(diff / 1000 / 60 / 60 % 24);
  const minutes = Math.floor(diff / 1000 / 60 % 60);



  console.log('diff', diff);

  if (diff > 0) {
    const info = vuln ?
    'These cookies are not protected by a secret key so they can be changed.' :
    'These cookies are protected by a secret key so they cannot be changed. They are also set to httpOnly so they cannot be accessed by JavaScript.' ;

    res.render('countdown', {
      days,
      hours,
      minutes,
      info
    });

  } else if (diff < 0) {
    res.render('secret', {});
  } else {
      res.render('error', {
        message: 'Something went wrong',
        error: {
        }
      })
  }
});

router.post('/xss', function(req, res, next) {
  const body = req.body;
  let xssMessage = body.xssMessage;

  if (!body.isVulnerable) {
    const window = new JSDOM('').window;
    const DOMPurify = createDOMPurify(window);
    xssMessage = escape(xssMessage);
    res.send(DOMPurify.sanitize(
      `<html>
        <body>
          <h1>Hi ${xssMessage}</h1>
        </body>
      </html>`
    ));
  } else {
    res.send(
      `<html>
        <body>
          <h1>Hi ${xssMessage}</h1>
        </body>
      </html>`
    );
  }
});

module.exports = router;
