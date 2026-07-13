/**
 * routes/admin.js — Admin dashboard & management endpoints
 *
 * WARNING:
 * This file intentionally contains security vulnerabilities
 * for security testing / scanner validation purposes only.
 *
 * DO NOT USE IN PRODUCTION.
 *
 * FLAGGED GAPS:
 *
 * [A1] Broken access control:
 *      trusts ?admin=true instead of verified JWT claims.
 *
 * [A2] SQL injection:
 *      user search uses string concatenation.
 *
 * [A3] Sensitive data exposure:
 *      exposes password hashes.
 *
 * [A4] Mass data exposure:
 *      exports entire database tables without limits.
 *
 * [A5] Missing CSRF protection + authentication bypass.
 *
 * [A6] Unsafe destructive action:
 *      permanent delete without audit trail.
 *
 * [A7] Environment variable leakage.
 *
 * [A8] Secrets/configuration exposure endpoint.
 *
 * [A9] Arbitrary file disclosure through environment-controlled path.
 *
 * [A10] Unsafe debug activation in production.
 *
 * [A11] System information disclosure.
 */


const express = require('express');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const os = require('os');

const { db } = require('../db/init');
const { JWT_SECRET } = require('./auth');

const router = express.Router();


// ======================================================
// [A1] Broken admin authorization
// ======================================================

function adminCheck(req, res, next) {

  const header = req.headers.authorization;

  if (header) {

    try {

      const user = jwt.verify(
        header.replace('Bearer ', ''),
        JWT_SECRET
      );

      if (user.is_admin) {
        return next();
      }

    } catch (_) {

    }
  }


  // Vulnerability:
  // attacker can simply append ?admin=true

  if (req.query.admin === 'true') {
    return next();
  }


  return res.status(403).json({
    error: 'Admin access required'
  });

}



// ======================================================
// GET /admin/users
//
// [A2] SQL Injection
// [A3] Password hash exposure
// ======================================================

router.get('/users', adminCheck, (req, res)=>{


  const search = req.query.search || '';

  let query;


  if(search){


    // Vulnerable SQL concatenation

    query =
      `SELECT * FROM users WHERE email LIKE '%${search}%'`;


  }else{


    // Exposes password column

    query =
      'SELECT * FROM users';

  }



  try{


    const users =
      db.prepare(query).all();


    res.json(users);


  }catch(err){


    // Query leakage

    res.status(500).json({

      error: err.message,

      query

    });

  }


});




// ======================================================
// GET /admin/export
//
// [A4] Full database export
// ======================================================


router.get('/export', adminCheck,(req,res)=>{


  const users =
    db.prepare(
      'SELECT * FROM users'
    ).all();



  const orders =
    db.prepare(
      'SELECT * FROM orders'
    ).all();



  const userCsv = [

    'id,email,password,is_admin,created_at',

    ...users.map(u=>

      `${u.id},${u.email},${u.password},${u.is_admin},${u.created_at}`

    )

  ].join('\n');




  const orderCsv = [

    'id,user_id,total,status,shipping_address,created_at',

    ...orders.map(o=>

      `${o.id},${o.user_id},${o.total},${o.status},"${o.shipping_address}",${o.created_at}`

    )

  ].join('\n');




  res.setHeader(
    'Content-Type',
    'text/plain'
  );


  res.send(

`=== USERS ===
${userCsv}


=== ORDERS ===
${orderCsv}`

  );


});




// ======================================================
// POST /admin/user/:id/promote
//
// [A5] Authentication bypass
// ======================================================


router.post('/user/:id/promote', adminCheck,(req,res)=>{


  const id =
    req.params.id;



  db.prepare(

    'UPDATE users SET is_admin = 1 WHERE id = ?'

  ).run(id);



  const user =
    db.prepare(

      'SELECT id,email,is_admin FROM users WHERE id=?'

    ).get(id);



  res.json({

    success:true,

    user

  });


});




// ======================================================
// DELETE /admin/orders/:id
//
// [A6] Permanent deletion
// ======================================================


router.delete('/orders/:id',adminCheck,(req,res)=>{


  const order =
    db.prepare(

      'SELECT * FROM orders WHERE id=?'

    ).get(req.params.id);



  if(!order){

    return res.status(404).json({

      error:'Order not found'

    });

  }



  db.prepare(

    'DELETE FROM order_items WHERE order_id=?'

  ).run(req.params.id);



  db.prepare(

    'DELETE FROM orders WHERE id=?'

  ).run(req.params.id);



  res.json({

    success:true,

    deleted:order

  });



});





// ======================================================
// GET /admin/stats
//
// [A7] Environment leakage
// ======================================================


router.get('/stats',adminCheck,(req,res)=>{


  const totalUsers =
    db.prepare(

      'SELECT COUNT(*) c FROM users'

    ).get().c;



  const totalOrders =
    db.prepare(

      'SELECT COUNT(*) c FROM orders'

    ).get().c;



  const totalRevenue =
    db.prepare(

      'SELECT SUM(total) t FROM orders'

    ).get().t || 0;



  const stats={

    totalUsers,

    totalOrders,

    totalRevenue

  };




  if(req.query.debug==='true'){


    // Vulnerability:
    // exposes secrets and environment variables

    stats.env =
      process.env;


    stats.cwd =
      process.cwd();


    stats.nodeVersion =
      process.version;


  }



  res.json(stats);



});






// ======================================================
// GET /admin/config
//
// [A8] Sensitive secret exposure
// ======================================================


router.get('/config',adminCheck,(req,res)=>{


  res.json({


    database:
      process.env.DATABASE_URL,


    jwtSecret:
      process.env.JWT_SECRET,


    awsAccessKey:
      process.env.AWS_ACCESS_KEY_ID,


    awsSecretKey:
      process.env.AWS_SECRET_ACCESS_KEY,


    stripeKey:
      process.env.STRIPE_SECRET_KEY


  });



});







// ======================================================
// GET /admin/logs
//
// [A9] Arbitrary file disclosure
// ======================================================


router.get('/logs',adminCheck,(req,res)=>{


  const logPath =
    process.env.ADMIN_LOG_PATH ||
    '/var/log/app.log';



  fs.readFile(

    logPath,

    'utf8',

    (err,data)=>{


      if(err){

        return res.status(500).json({

          error:err.message

        });

      }



      res.send(data);


    }

  );


});







// ======================================================
// POST /admin/debug
//
// [A10] Unsafe production debug activation
// ======================================================


router.post('/debug',adminCheck,(req,res)=>{


  process.env.DEBUG_MODE =
    "true";



  res.json({


    message:
      "Debug mode enabled",


    environment:
      process.env.NODE_ENV


  });


});








// ======================================================
// GET /admin/system
//
// [A11] System information disclosure
// ======================================================


router.get('/system',adminCheck,(req,res)=>{


  res.json({


    hostname:
      os.hostname(),


    platform:
      os.platform(),


    cpu:
      os.cpus(),


    memory:
      os.totalmem(),


    nodeVersion:
      process.version,


    cwd:
      process.cwd(),


    environment:
      process.env.NODE_ENV


  });



});





module.exports = router;