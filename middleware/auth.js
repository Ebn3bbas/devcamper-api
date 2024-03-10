const jwt = require("jsonwebtoken");
const asyncHandler = require("../middleware/async");
const User = require("../models/User");
const ErrorResponse = require("../utils/errorResponse");

// Protect routes
exports.protect = asyncHandler(async (req, res, next) => {
  let token;

  // Get token from header if it exists
  if (
    req.headers.authorization &&
    req.headers.authorization.startsWith("Bearer")
  ) {
    // set token from Bearer token header
    token = req.headers.authorization.split(" ")[1];
  } else if (req.query.token) {
    // Set token from cookie
    token = req.query.token;
  }

  // Make sure token exists
  if (!token)
    return next(
      new ErrorResponse(`Not authorized to access this resource`, 401)
    );
  try {
    // Verify token
    const decoded = await jwt.verify(token, process.env.JWT_SECRET);

    req.user = await User.findById(decoded.id);

    next();
  } catch (err) {
    return next(
      new ErrorResponse(
        `Not authorized to access this resource: ${err.message}`,
        401
      )
    );
  }
});

// Grant access to specific roles
exports.authorize = (...roles) => {
  return (req, res, next) => {
    if (!roles.includes(req.user.role)) {
      return next(
        new ErrorResponse(
          `User role ${req.user.role} is not authorized to access this resource`,
          403
        )
      );
    }
    next();
  };
};
