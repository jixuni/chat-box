const bcrypt = require("bcryptjs");

const { User } = require("../models");

module.exports = {
  Query: {
    getUsers: async () => {
      try {
        const users = await User.findAll();

        return users;
      } catch (err) {
        console.log(err);
      }
    },
  },
  Mutation: {
    register: async (_, args) => {
      let { username, email, password, confirmPassword } = args;

      try {
        //Todo: validate input data

        //Todo: check if username/email exists

        //Todo: hash password
        password = await bcrypt.hash(password, 6);
        //Todo: create user
        const user = await User.create({
          username,
          email,
          password,
        });
        //Todo: return user
        return user;
      } catch (err) {
        console.log(err);
        throw err;
      }
    },
  },
};
