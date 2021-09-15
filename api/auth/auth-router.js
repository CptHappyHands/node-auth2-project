const bcrypt = require("bcryptjs");
const router = require("express").Router();
const { checkUsernameExists, validateRoleName } = require("./auth-middleware");
const Users = require("../users/users-model");
const tokenBuilder = require("./token-builder");
// const { JWT_SECRET } = require("../secrets"); // use this secret!

router.post("/register", validateRoleName, (req, res, next) => {
  const { username, password } = req.body;
  const { role_name } = req;
  const hash = bcrypt.hashSync(password, 8);
  Users.add({ username, password: hash, role_name })
    .then((data) => {
      res.status(201).json(data);
    })
    .catch(next);
  /**
    [POST] /api/auth/register { "username": "anna", "password": "1234", "role_name": "angel" }

    response:
    status 201
    {
      "user"_id: 3,
      "username": "anna",
      "role_name": "angel"
    }
   */
});

router.post("/login", checkUsernameExists, (req, res, next) => {
  if (bcrypt.compareSync(req.body.password, req.user.password)) {
    const token = tokenBuilder(req.user);
    res.status(200).json({
      message: `${req.user.username} is back!`,
      token,
    });
  } else {
    next({
      status: 401,
      message: "Invalid credentials",
    });
  }
  // let { username, password } = req.body;

  // Users.findBy({ username })
  //   .then((user) => {
  //     if (user && bcrypt.compareSync(password, user.password)) {
  //       console.log(user);
  //       const token = tokenBuilder(user);
  //       res.status(200).json({
  //         message: `${req.user.username} is back!`,
  //         token,
  //       });
  //     } else {
  //       next({ status: 401, message: "Invalid Credentials" });
  //     }
  //   })
  //   .catch(next);
  // try {
  //   const { username, password } = req.body;
  //   const existing = await Users.findBy({ username });
  //   if (existing.length && bcrypt.compareSync(password, existing[0].password)) {
  //     req.user = existing[0];
  //     const token = tokenBuilder(existing);
  //     res.json({
  //       status: 200,
  //       message: `${req.user.username} is back!`,
  //       token,
  //     });
  //   } else {
  //     next({ status: 401, message: "Invalid credentials" });
  //   }
  // } catch (err) {
  //   next(err);
  // }

  /**
    [POST] /api/auth/login { "username": "sue", "password": "1234" }

    response:
    status 200
    {
      "message": "sue is back!",
      "token": "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.ETC.ETC"
    }

    The token must expire in one day, and must provide the following information
    in its payload:

    {
      "subject"  : 1       // the user_id of the authenticated user
      "username" : "bob"   // the username of the authenticated user
      "role_name": "admin" // the role of the authenticated user
    }
   */
});

module.exports = router;
