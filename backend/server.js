const express = require('express');
const mysql = require('mysql2');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');

const app = express();
app.use(cors());
app.use(express.json());

const nodemailer = require('nodemailer');
const twilio = require('twilio');

//twilio setup
const client = twilio(process.env.TWILIO_SID, process.env.TWILIO_AUTH);

const SECRET_KEY = process.env.JWT_SECRET; 

// MySQL DB Connection
  const db = mysql.createConnection({
  host: process.env.DB_HOST,
  user: process.env.DB_USER,
  password: process.env.DB_PASSWORD,
  database: process.env.DB_NAME
});

db.connect(err => {
  if (err) throw err;
  console.log('Connected to MySQL');
});



// Helper Functions
function generateUserId(name, dob) {
  const namePart = name.slice(0, 4).toLowerCase();
  const yearPart = new Date(dob).getFullYear().toString().slice(-2);
  
  const randomPart = Math.random().toString(36).substring(2, 6); // generates 4 random alphanumeric characters
    return namePart + yearPart + randomPart;

}

function calculateAge(dob) {
  const birthDate = new Date(dob);
  const today = new Date();
  let age = today.getFullYear() - birthDate.getFullYear();
  const m = today.getMonth() - birthDate.getMonth();
  if (m < 0 || (m === 0 && today.getDate() < birthDate.getDate())) {
    age--;
  }
  return age;
}


function generateOTP() {
  return Math.floor(100000 + Math.random() * 900000).toString();
}





//middleware for JWT authentication

const authenticateUser=(req,res,next)=>{
  const token=req.header('Authorization');
  if(!token){
    console.log('Authorization header is missing');
    return res.status(401).send('Access Denied');
  }
  const tokenParts=token.split(' ');
  if(tokenParts.length!=2  || tokenParts[0]!='Bearer')
  {
    console.log('token format incorrect:',token);
    return res.status(400).send('invalid token')
  }

  try{
    const verified=jwt.verify(tokenParts[1],SECRET_KEY);
    req.user=verified;   //decode token attached to user
    next(); //proceed to next middleware
    }
    catch(err){
      console.log(err.message);
      res.status(400).send('invalid token')
    }
}



//send email otp
app.post('/send-email-otp', (req, res) => {
  const { email } = req.body;
  const emailOtp = generateOTP();

  db.query(`SELECT * FROM otp_verification WHERE email=?`, [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length > 0) {
      const attempts = results[0].email_otp_attempts || 0;
      if (attempts >= 3) return res.status(429).json({ error: 'OTP send limit reached. Try again later.' });

      db.query(
        `UPDATE otp_verification SET email_otp=?, email_otp_created_at=NOW(), email_otp_attempts=email_otp_attempts+1, is_email_verified=FALSE WHERE email=?`,
        [emailOtp, email],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });
          sendEmailOtp(email, emailOtp, res);
        }
      );
    } else {
      db.query(
        `INSERT INTO otp_verification (email, email_otp, email_otp_created_at, email_otp_attempts) VALUES (?, ?, NOW(), 1)`,
        [email, emailOtp],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });
          sendEmailOtp(email, emailOtp, res);
        }
      );
    }
  });
});

//setup nodemailer
function sendEmailOtp(email, otp, res) {
  const transporter = nodemailer.createTransport({
    service: process.env.EMAIL_SERVICE,
    auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS }
  });

  const mailOptions = {
    from: process.env.EMAIL_USER,
    to: email,
    subject: 'Your OTP Code',
    text: `Your email OTP is: ${otp}`
  };

  transporter.sendMail(mailOptions, (error) => {
    if (error) return res.status(500).json({ error: 'Email sending failed' });
    res.json({ message: 'Email OTP sent successfully' });
  });
}
//verify email otp
app.post('/verify-email-otp', (req, res) => {
  const { email, otp } = req.body;

  db.query(`SELECT * FROM otp_verification WHERE email = ?`, [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: 'Email not found' });

    const record = results[0];
    const now = new Date();
    const otpTime = new Date(record.email_otp_created_at);
    const diffMinutes = Math.floor((now - otpTime) / 60000);

    if (diffMinutes > 10) {
      return res.status(400).json({ error: 'OTP expired' });
    }

    if (record.email_otp !== otp) {
      return res.status(401).json({ error: 'Invalid OTP' });
    }

    db.query(`UPDATE otp_verification SET is_email_verified=TRUE WHERE email=?`, [email], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Email verified successfully' });
    });
  });
});


//send phone otp
app.post('/send-phone-otp', (req, res) => {
  const { email, phone } = req.body;
  const phoneOtp = generateOTP();

  db.query(`SELECT * FROM otp_verification WHERE email=?`, [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length > 0) {
      const attempts = results[0].phone_otp_attempts || 0;
      if (attempts >= 3) return res.status(429).json({ error: 'OTP send limit reached. Try again later.' });

      db.query(
        `UPDATE otp_verification SET phone=?, phone_otp=?, phone_otp_created_at=NOW(), phone_otp_attempts=phone_otp_attempts+1, is_phone_verified=FALSE WHERE email=?`,
        [phone, phoneOtp, email],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });
          sendSMSOtp(phone, phoneOtp, res);
        }
      );
    } else {
      db.query(
        `INSERT INTO otp_verification (phone, phone_otp, phone_otp_created_at, phone_otp_attempts) VALUES (?, ?, NOW(), 1)`,
        [phone, phoneOtp],
        (err) => {
          if (err) return res.status(500).json({ error: err.message });
          sendSMSOtp(phone, phoneOtp, res);
        }
      );
    }
  });
});
//verify phone otp
app.post('/verify-phone-otp', (req, res) => {
  const { email, phone, otp } = req.body;

  db.query(`SELECT * FROM otp_verification WHERE email = ?`, [email], (err, results) => {
    if (err) return res.status(500).json({ error: err.message });
    if (results.length === 0) return res.status(404).json({ error: 'User not found' });

    const record = results[0];
    const now = new Date();
    const otpTime = new Date(record.phone_otp_created_at);
    const diffMinutes = Math.floor((now - otpTime) / 60000);

    if (diffMinutes > 10) {
      return res.status(400).json({ error: 'OTP expired' });
    }

    if (record.phone !== phone) {
      return res.status(400).json({ error: 'Phone number mismatch with email' });
    }

    if (record.phone_otp !== otp) {
      return res.status(401).json({ error: 'Invalid OTP' });
    }

    db.query(`UPDATE otp_verification SET is_phone_verified=TRUE WHERE email=?`, [email], (err) => {
      if (err) return res.status(500).json({ error: err.message });
      res.json({ message: 'Phone verified successfully' });
    });
  });
});

function sendSMSOtp(phone, otp, res) {
  client.messages
    .create({
      body: `Your verification OTP is: ${otp}`,
      from: process.env.TWILIO_PHONE,
      to: phone
    })
    .then(() => res.json({ message: 'Phone OTP sent successfully' }))
    .catch((error) => {
      console.error(error);
      res.status(500).json({ error: 'SMS sending failed' });
    });
}






// register after verifying email and mobile number

app.post('/users/register', async (req, res) => {
  const { name, email, phone, password, dob, role, preferences } = req.body;

  const checkSQL = `SELECT * FROM otp_verification WHERE email = ? AND phone = ?`;
  db.query(checkSQL, [email, phone], async (err, results) => {
    if (err) return res.status(500).json({ error: err.message });

    if (results.length === 0) {
      return res.status(400).json({ error: 'Please verify email and phone first' });
    }

    const record = results[0];
    if (!record.is_email_verified || !record.is_phone_verified) {
      return res.status(400).json({ error: 'Email or phone not verified' });
    }

    // Generate unique user ID
    let id;
    let isUnique = false;
    while (!isUnique) {
      id = generateUserId(name, dob);
      const [existing] = await new Promise((resolve, reject) => {
        db.query(`SELECT id FROM users WHERE id = ?`, [id], (err, result) => {
          if (err) reject(err);
          else resolve(result);
        });
      });
      if (!existing) isUnique = true;
    }

    const age = calculateAge(dob);
    const hashedPassword = await bcrypt.hash(password, 10);

    const insertSQL = `
      INSERT INTO users (id, name, email, phone, password, dob, age, role, preferences)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
    `;
    db.query(insertSQL, [id, name, email, phone, hashedPassword, dob, age, role, preferences || 'user'], (err2, result) => {
      if (err2) return res.status(500).json({ error: err2.message });

      res.status(201).json({ message: 'User registered successfully', userId: id });
    });
  });
});

//  login user with token
app.post('/users/login', (req, res) => {
  const { email, password } = req.body;
  const sql='SELECT * FROM users WHERE email = ?'
  db.query(sql, [email], async (err, results) => {
    if (err || results.length === 0) return res.status(401).json({ error: 'Invalid credentials' });

    const user = results[0];
    const match = await bcrypt.compare(password, user.password);
    if (!match) return res.status(401).json({ error: 'Invalid credentials' });

    const token = jwt.sign({ id: user.id, role: user.role }, SECRET_KEY, { expiresIn: '1d' });
    res.json({ message: 'Login successful', token });
  });
});

// logout  user (dummy – token will expire in 1 day)
app.post('/users/logout', (req, res) => {
  res.json({ message: 'Logout successful (handled on frontend by deleting token)' });
});

// fetch user detail by userId
app.get('/users/:userId', (req, res) => {
  const { userId } = req.params;
  const sql='SELECT id, name, email, phone, dob, age, role, preferences FROM users WHERE id = ?';
  db.query(sql, [userId], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: 'User not found' });
    res.json(results[0]);
  });
});


//normal field  update
app.put('/users/:userId', authenticateUser, (req, res) => {
  const { userId } = req.params;
  const { name, dob, role, preferences } = req.body;
  const age = calculateAge(dob);

  const sql = `
    UPDATE users 
    SET name = ?, dob = ?, age = ?, role = ?, preferences = ?
    WHERE id = ?
  `;
  db.query(sql, [name, dob, age, role, preferences, userId], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    if (result.affectedRows === 0) return res.status(404).json({ error: 'User not found' });
    res.json({ message: 'Profile updated successfully' });
  });
});

//password change with  mobile otp
app.post('/users/request-password-change', authenticateUser, (req, res) => {
  const { userId } = req.body;

  db.query(`SELECT phone FROM users WHERE id=?`, [userId], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: 'User not found' });

    const phone = results[0].phone;
    const otp = generateOTP();

    db.query(
      `UPDATE otp_verification SET phone_otp=?, phone_otp_created_at=NOW(), phone_otp_attempts=phone_otp_attempts+1, is_phone_verified=FALSE WHERE phone=?`,
      [otp, phone],
      (err2) => {
        if (err2) return res.status(500).json({ error: err2.message });
        sendSMSOtp(phone, otp, res);
      }
    );
  });
});

//verify otp and changed password
app.post('/users/verify-password-change', async (req, res) => {
  const { userId, newPassword, otp } = req.body;

  db.query(`SELECT phone FROM users WHERE id = ?`, [userId], async (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: 'User not found' });

    const phone = results[0].phone;

    db.query(`SELECT * FROM otp_verification WHERE phone = ?`, [phone], async (err2, result2) => {
      if (err2 || result2.length === 0) return res.status(404).json({ error: 'OTP not found' });

      const record = result2[0];
      const otpTime = new Date(record.phone_otp_created_at);
      if (isOtpExpired(otpTime)) return res.status(400).json({ error: 'OTP expired' });
      if (record.phone_otp !== otp) return res.status(401).json({ error: 'Invalid OTP' });

      const hashed = await bcrypt.hash(newPassword, 10);
      db.query(`UPDATE users SET password = ? WHERE id = ?`, [hashed, userId], (err3) => {
        if (err3) return res.status(500).json({ error: err3.message });
        res.json({ message: 'Password updated successfully' });
      });
    });
  });
});

//email change request by userId
app.post('/users/request-email-change', authenticateUser, (req, res) => {
  const { userId, newEmail } = req.body;
  const otp = generateOTP();

  db.query(`SELECT email FROM users WHERE id = ?`, [userId], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: 'User not found' });

    db.query(
      `INSERT INTO otp_verification (email, email_otp, email_otp_created_at, email_otp_attempts) 
       VALUES (?, ?, NOW(), 1) ON DUPLICATE KEY UPDATE 
       email_otp=?, email_otp_created_at=NOW(), email_otp_attempts=email_otp_attempts+1, is_email_verified=FALSE`,
      [newEmail, otp, otp],
      (err2) => {
        if (err2) return res.status(500).json({ error: err2.message });
        sendEmailOtp(newEmail, otp, res);
      }
    );
  });
});

//verify modified email
app.post('/users/verify-email-change', authenticateUser, (req, res) => {
  const { userId, newEmail, otp } = req.body;

  db.query(`SELECT * FROM otp_verification WHERE email = ?`, [newEmail], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: 'Email not found' });

    const record = results[0];
    if (isOtpExpired(record.email_otp_created_at)) return res.status(400).json({ error: 'OTP expired' });
    if (record.email_otp !== otp) return res.status(401).json({ error: 'Invalid OTP' });

    db.query(`UPDATE users SET email = ? WHERE id = ?`, [newEmail, userId], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });

      // Remove old email from OTP table
      db.query(`DELETE FROM otp_verification WHERE email != ? AND phone IS NULL`, [newEmail], () => {
        res.json({ message: 'Email updated successfully' });
      });
    });
  });
});

//phone change request by userid without check mail
app.post('/users/request-phone-change', authenticateUser, (req, res) => {
  const { userId, newPhone } = req.body;
  const otp = generateOTP();

 
  db.query(`SELECT * FROM users WHERE id = ?`, [userId], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: 'User not found' });




   db.query(
      `INSERT INTO otp_verification (phone, phone_otp, phone_otp_created_at, phone_otp_attempts,email)
       VALUES (?, ?, NOW(), 1,'')
       ON DUPLICATE KEY UPDATE 
       phone_otp = ?, phone_otp_created_at = NOW(), phone_otp_attempts = phone_otp_attempts + 1, is_phone_verified = FALSE`,
      [newPhone, otp, otp],
      (err2) => {
        if (err2) return res.status(500).json({ error: err2.message });

        //  Send SMS OTP
        sendSMSOtp(newPhone, otp, res);  
      }
    );
  });
});

//verify modified phone number
app.post('/users/verify-phone-change', authenticateUser, (req, res) => {
  const { userId, newPhone, otp } = req.body;

  // Check OTP validity
  db.query(`SELECT * FROM otp_verification WHERE phone = ?`, [newPhone], (err, results) => {
    if (err || results.length === 0) return res.status(404).json({ error: 'OTP record not found for this phone' });

    const record = results[0];
    const otpTime = new Date(record.phone_otp_created_at);

    if (isOtpExpired(otpTime)) return res.status(400).json({ error: 'OTP expired' });
    if (record.phone_otp !== otp) return res.status(401).json({ error: 'Invalid OTP' });

    // Update phone number in users table
    db.query(`UPDATE users SET phone = ? WHERE id = ?`, [newPhone, userId], (err2) => {
      if (err2) return res.status(500).json({ error: err2.message });

      // Delete all old phone OTP entries except new one
      db.query(`DELETE FROM otp_verification WHERE phone != ? AND email IS NULL`, [newPhone], () => {
        res.json({ message: 'Phone number updated successfully' });
      });
    });
  });
});




//delete user detail
app.delete('/users/:userId',authenticateUser,(req,res)=>{
  const {userId}=req.params;
  const sql='DELETE from users where id=?'
  db.query(sql,[userId],(err,result)=>{
    if(err){
      console.error(err.message);
      res.status(500).send('internal server error')
    }
    else if(result.affectedRows===0)
    {
      res.status(403).send('user not found')
    }
    else{
      res.send('user account deleted')
    }
  })
})


//  Start Server
app.listen(process.env.PORT, () => {
  console.log(`User Auth Service running on port ${process.env.PORT}`);
});


