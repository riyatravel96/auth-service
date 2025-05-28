const express = require('express');
const mysql = require('mysql2');
require('dotenv').config();
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const cors = require('cors');


const app = express();
app.use(cors());
app.use(express.json());

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
  return namePart + yearPart;
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





//  register user
app.post('/users/register', async (req, res) => {
  const { name, email, phone, password, dob, role, preferences } = req.body;
  const id = generateUserId(name, dob);
  const age = calculateAge(dob);
  const hashedPassword = await bcrypt.hash(password, 10);

  const sql = 'INSERT INTO users (id, name, email, phone, password, dob, age, role,preferences) VALUES (?, ?, ?, ?, ?, ?, ?, ?,?)';
  db.query(sql, [id, name, email, phone, hashedPassword, dob, age, role, preferences || 'user'], (err, result) => {
    if (err) return res.status(500).json({ error: err.message });
    res.status(201).json({ message: 'User registered successfully', userId: id });
  });
});


//  login user
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



//update user detail

app.put('/users/:userId',authenticateUser, async (req, res) => {
  const { userId } = req.params;
  const { name, email, phone, dob , role, preferences} = req.body;

  const age = dob ? calculateAge(dob) : null;


  const sql='UPDATE users SET name = ?,email=?, phone = ? ,dob=?,age=?,role=?,preferences=? WHERE id = ?';
   db.query(sql, [name, email,phone,dob,age,role,preferences, userId], (err, result) => {
    if(err){
      console.error(err.message);
      res.status(500).send('internal error')
    }
    else if (res.affectedRows===0)
    {
      res.status(403).send('user not found')
    }
    else{
      res.send('user profile updated')
    }
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


