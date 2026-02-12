
const express = require('express');
const app = express();
require('dotenv').config();
console.log('JWT_SECRET:', process.env.JWT_SECRET);

const Transaction = require('./models/Transaction.js');
const cors = require('cors');
const mongoose = require('mongoose');
const pasth = require('path');
const bcrypt = require('bcrypt');
const User = require('./models/User');
const jwt = require('jsonwebtoken');


app.set('view engine', 'ejs');

app.use(cors({
  origin: 
  'http://localhost:3000', // React app URL
  methods: ['GET', 'POST', 'DELETE'],
  allowedHeaders: ['Content-Type', 'Authorization']
}))

app.use(express.json());

function authMiddleware(req, res, next) {
  const authHeader = req.headers.authorization;

  if (!authHeader) {
    return res.status(401).json({ error: 'No token' });
  }

  const token = authHeader.split(' ')[1];

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    console.log('Decoded token:', decoded);
    req.userId = decoded.userId;
    next();
  } catch (err) {
    console.log('JWT verify error:', err);
    res.status(401).json({ error: 'Invalid token' });
  }
}

app.get('/api/transactions', authMiddleware, async (req, res) => {
  console.log('Fetching transactions for user:', req.userId);
  await mongoose.connect(process.env.MONGO_URL);
  const transactions = await Transaction.find({userId: req.userId});
  res.json(transactions);
});


app.post('/api/transactions', authMiddleware, async (req, res) => {
  console.log('Authorization header:', req.headers.authorization);
  console.log('Decoded token:', req.userId);
  console.log('Request body:', req.body);


  await mongoose.connect(process.env.MONGO_URL);
  //const{name,description,datetime,price} = req.body;
  //const transaction = await Transaction.create({name,description,datetime,price});
  
  console.log('Creating transaction', req.body, 'for user', req.userId);

  try {
    const transaction = await Transaction.create({ ...req.body, userId: req.userId });
    res.json(transaction);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.delete('/api/transactions/:id', authMiddleware, async (req, res) => {
  try {
    await mongoose.connect(process.env.MONGO_URL);

    const { id } = req.params;

    const deletedTransaction = await Transaction.findByIdAndDelete(id);

    if (!deletedTransaction) {
      return res.status(404).json({ error: 'Transaction not found' });
    }

    res.json({ success: true, id });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/signup', async (req, res) => {
  try {
    await mongoose.connect(process.env.MONGO_URL);
    const { username, password } = req.body;

    // ✅ Password validation
    const isLongEnough = password.length >= 8;
    const hasUppercase = /[A-Z]/.test(password);
    const hasNumber = /\d/.test(password);

    if (!isLongEnough || !hasUppercase || !hasNumber) {
      return res.status(400).json({ error: 'Password must be at least 8 characters, include an uppercase letter and a number' });
    }

    // ✅ Hash password
    const hashedPassword = await bcrypt.hash(password, 10);

    // ✅ Create user
    const user = await User.create({ username, password: hashedPassword });

    res.status(201).json({ message: 'User created' }); // success

  } catch (err) {
    // if username already exists (unique index violation)
    if (err.code === 11000) {
      return res.status(400).json({ error: 'Username already exists' });
    }
    console.error(err);
    res.status(500).json({ error: 'Server error' });
  }
});



app.post('/api/login', async (req, res) => {
  await mongoose.connect(process.env.MONGO_URL);
  const { username, password } = req.body;

  const user = await User.findOne({ username });
  if (!user) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const passwordMatch = await bcrypt.compare(password, user.password);
  if (!passwordMatch) {
    return res.status(401).json({ error: 'Invalid credentials' });
  }

  const token = jwt.sign(
    { userId: user._id.toString() },
    process.env.JWT_SECRET,
    { expiresIn: '1d' }
  );

  res.json({ token }); // ✅ always JSON
});


app.listen(4000, () => {
  console.log('Server is running on port 4000');
});

