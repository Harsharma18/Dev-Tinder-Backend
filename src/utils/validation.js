const validator = require("validator");

const validateSignUpdata = (req) => {
  const { firstName, lastName, email, password } = req.body;

  if (!firstName || !lastName) {
    throw new Error("Name is not valid!");
  }

  const normalizedEmail = validator.normalizeEmail(email);

  if (!normalizedEmail || !validator.isEmail(normalizedEmail)) {
    throw new Error("Email is not valid!");
  }

  if (
    !validator.isStrongPassword(password, {
      minLength: 8,
      minLowercase: 1,
      minUppercase: 1,
      minNumbers: 1,
      minSymbols: 1,
    })
  ) {
    throw new Error(
      "Password must be at least 8 characters and include uppercase, lowercase, number, and symbol."
    );
  }
};

module.exports = { validateSignUpdata };
