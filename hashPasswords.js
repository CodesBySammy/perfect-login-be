const bcrypt = require('bcrypt');

const users = [
  "password12345678",
  "password12345679",
  // Add similar passwords for users 3 to 50
];

const saltRounds = 10;

const hashPasswords = async () => {
  for (const password of users) {
    const hash = await bcrypt.hash(password, saltRounds);
    console.log(`Password: ${password}, Hash: ${hash}`);
  }
};

hashPasswords().catch(err => console.error(err));
