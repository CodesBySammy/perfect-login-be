const express = require('express');
const bodyParser = require('body-parser');
const cors = require('cors');
const bcrypt = require('bcrypt');
const jwt = require('jsonwebtoken');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(cors());
app.use(bodyParser.json());

const SECRET_KEY = 'e67f1b5c2aebc6dfd3f85bd9ae3f9023e02f103d4fa2a7a6b5e9fb73cf57ef6b'; // Use an environment variable in production
const saltRounds = 10;

// Sample user data with plaintext passwords for initial setup
const usersPlaintext = [
  { id: "user1", password: "password12345678" }, // Password for user1
  { id: "user2", password: "password12345679" }, // Password for user2
  // Add other users with plaintext passwords here
];

// Function to hash passwords and save to file
const hashPasswords = async () => {
  const hashedUsers = await Promise.all(usersPlaintext.map(async (user) => {
    const hashedPassword = await bcrypt.hash(user.password, saltRounds);
    return { id: user.id, password: hashedPassword };
  }));

  // Save the hashed users to a file
  fs.writeFileSync(path.join(__dirname, 'hashed_users.json'), JSON.stringify(hashedUsers, null, 2));
  console.log('Hashed passwords have been saved.');
};

// Hash passwords if file doesn't exist
const hashedUsersFilePath = path.join(__dirname, 'hashed_users.json');
let hashedUsers = [];

if (fs.existsSync(hashedUsersFilePath)) {
  hashedUsers = JSON.parse(fs.readFileSync(hashedUsersFilePath));
} else {
  // Uncomment the following line to hash passwords and save them if the file does not exist
  hashPasswords().catch(err => console.error(err));
}

// Middleware to protect routes
const authenticateToken = (req, res, next) => {
  const authHeader = req.headers['authorization'];
  const token = authHeader && authHeader.split(' ')[1];

  if (token == null) return res.sendStatus(401);

  jwt.verify(token, SECRET_KEY, (err, user) => {
    if (err) return res.sendStatus(403);
    req.user = user;
    next();
  });
};

// Endpoint for login
app.post('/login', async (req, res) => {
  const { id, password } = req.body;
  const user = hashedUsers.find(user => user.id === id);

  if (user && await bcrypt.compare(password, user.password)) {
    const token = jwt.sign({ id: user.id }, SECRET_KEY, { expiresIn: '1h' });
    res.json({ success: true, token });
  } else {
    res.status(401).json({ success: false, message: 'Invalid credentials' });
  }
});

// Protected route example
app.get('/protected', authenticateToken, (req, res) => {
  res.json({ message: 'This is a protected route', user: req.user });
});

// Serve static files
app.use(express.static('public'));

// Start the server
app.listen(5000, () => {
  console.log('Server running on port 5000');
});
