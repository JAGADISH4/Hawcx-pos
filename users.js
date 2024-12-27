const bcrypt = require('bcrypt');

const users = [
  {
    username: 'john',
    password: bcrypt.hashSync('password123', 10),
    email: 'john@example.com',
  },
];

module.exports = { users };
