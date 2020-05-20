const express = require("express");
const app = express();
const jwt = require("jsonwebtoken");

const { mongoose } = require("./db/mongoose");

const bodyParser = require("body-parser");

// Load in mongoose models
const { List, Task, User } = require("./db/models/index");

/* MIDDLEWARE */

// CORS Middleware
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*"); // Your domain
  res.header(
    "Access-Control-Allow-Methods",
    "GET, POST, HEAD, OPTIONS, PUT, PATCH, DELETE"
  );
  res.header(
    // "Access-Control-Allow-Headers",
    // "Origin, X-Requested-With, Content-Type, Accept"
    "Access-Control-Allow-Headers",
    "*"
  );
  res.header(
    "Access-Control-Expose-Headers",
    "x-access-token, x-refresh-token"
  );
  next();
});

// Load Middleware
app.use(bodyParser.json());

// Check if the request has a valid jwt token
let authenticate = (req, res, next) => {
  let token = req.header("x-access-token");
  // Verify the jwt
  jwt.verify(token, User.getJwtSecret(), (err, decoded) => {
    if (err) {
      // There was an error
      // jwt is invalid - DO NOT AUTHENTICATE
      res.status(401).send(err);
    } else {
      // jwt is valid
      req.user_id = decoded._id;
      next();
    }
  });
};

// Verify Refresh Token MiddleWare (Which will be verifying the session)
let verifySession = (req, res, next) => {
  // grab the refresh token
  let refreshToken = req.header("x-refresh-token");
  let _id = req.header("_id");

  User.findByIdAndToken(_id, refreshToken)
    .then((user) => {
      if (!user) {
        // User cannot be found
        // return Promise.reject({
        //   error:
        //     "User not found. Make sure the refresh token and user id are correct",
        // });
        Promise.reject(
          "User not found. Make sure the refresh token and user id are correct"
        );
      }
      // The user was found
      // Therefore the refresh token exists in the database - we still have to check if it has expired
      req.user_id = user._id;
      req.userObject = user;
      req.refreshToken = refreshToken;
      let isSessionValid = false;
      user.sessions.forEach((session) => {
        if (session.token === refreshToken) {
          // check if the session has expired
          if (User.hasRefreshTokenExpired(session.expiresAt) === false) {
            // refresh token has not expired
            isSessionValid = true;
          }
        }
      });
      if (isSessionValid) {
        // The session is valid - call next() to continue with processing the web request
        next();
      } else {
        // The session is not valid
        // return Promise.reject({
        //   error: "Referesh token has expired or the session is invalid",
        // });
        return Promise.reject(
          "Referesh token has expired or the session is invalid"
        );
      }
    })
    .catch((e) => {
      res.status(401).send(e);
    });
};

/* END MIDDLEWARE */

// ROUTE HANDLERS

// LIST ROUTES

// GET /lists
// Purpose: Get all lists
app.get("/lists", authenticate, (req, res) => {
  //   return an array of all the lists that belong to the authenticated user
  List.find({ _userId: req.user_id })
    .then((lists) => {
      res.send(lists);
    })
    .catch((e) => {
      res.send(e);
    });
});

// POST /lists
// Purpose: create a list
app.post("/lists", authenticate, (req, res) => {
  // create a list and return the created list to the user
  let title = req.body.title;
  let newList = new List({ title, _userId: req.user_id });
  newList
    .save()
    .then((listDoc) => {
      res.send(listDoc).catch((e) => {
        res.send(e);
      });
    })
    .catch((e) => {
      res.send(e);
    });
});

// PATCH /lists/:id
// Purpose: Update a specifeid list
app.patch("/lists/:id", authenticate, (req, res) => {
  // Update the list with the specified id
  console.log(req.params.id);
  console.log(req.user_id);
  List.findOneAndUpdate(
    { _id: req.params.id, _userId: req.user_id },
    {
      $set: req.body,
    },
    { new: true },
    (err, result) => {
      if (err) {
        res.send(err);
      } else {
        // console.log(result);
        res.sendStatus(200);
      }
    }
  );
});

// DELETE /lists/:id
// Purpose: Delete a list
app.delete("/lists/:id", authenticate, (req, res) => {
  // Delete the list with the specified id
  List.findOneAndRemove({ _id: req.params.id, _userId: req.user_id })
    .then((removedListDocument) => {
      res.send(removedListDocument);
      // Delete all tasks in this list
      deleteTaskFromList(removedListDocument._id);
    })
    .catch((e) => {
      res.send(e);
    });
});

// GET /list/:listId/tasks
// Purpose: Get all tasks in a specified list
app.get("/lists/:listId/tasks", authenticate, (req, res) => {
  // return all tasks that belong to the specified list
  Task.find({ _listId: req.params.listId })
    .then((tasks) => {
      res.send(tasks);
    })
    .catch((e) => {
      res.send(e);
    });
});

// GET /lists/:listId/tasks/:taskId
// PURPOSE: Get the task with the taskId from the listId
// app.get("/lists/:listId/tasks/:taskId", (req, res) => {
//   // Get task from specified listId and taskId
//   Task.findOne({
//     _id: req.params.taskId,
//     _listId: req.params.listId,
//   })
//     .then((task) => {
//       res.send(task);
//     })
//     .catch((e) => {
//       res.send(e);
//     });
// });

// POST /lists/:listId/tasks
// Purpose: Create a new task in a specified list
app.post("/lists/:listId/tasks", authenticate, (req, res) => {
  // Create a task in the specified list
  List.findOne({ _id: req.params.listId, _userId: req.user_id })
    .then((list) => {
      if (list) {
        // The authenticated user is the list owner and can therefore create task
        return true;
      } else {
        return false;
      }
    })
    .then((canCreateTask) => {
      if (canCreateTask) {
        let newTask = new Task({
          title: req.body.title,
          _listId: req.params.listId,
        });
        newTask
          .save()
          .then((newTaskDoc) => {
            res.send(newTaskDoc);
          })
          .catch((e) => {
            res.send(e);
          });
      } else {
        res.sendStatus(404);
      }
    });
});

// PATCH /lists/:listId/tasks/:taskId
// Purpose: Update an existing task
app.patch("/lists/:listId/tasks/:taskId", authenticate, (req, res) => {
  // Update an existing task for the specified list
  List.findOne({ _id: req.params.listId, _userId: req.user_id })
    .then((list) => {
      if (list) {
        // The authenticated user is the list owner and can therefore update task
        return true;
      } else {
        return false;
      }
    })
    .then((canUpdateTask) => {
      if (canUpdateTask) {
        Task.findOneAndUpdate(
          {
            _id: req.params.taskId,
            _listId: req.params.listId,
          },
          {
            $set: req.body,
          }
        )
          .then(() => {
            res.sendStatus(200);
          })
          .catch((e) => {
            res.send(e);
          });
      } else {
        res.sendStatus(404);
      }
    });
});

// DELETE /lists/:listId/tasks/:taskId
// Purpose: Delete an existing task
app.delete("/lists/:listId/tasks/:taskId", (req, res) => {
  // Delete an existing task for a list
  List.findOne({ _id: req.params.listId, _userId: req.user_id })
    .then((list) => {
      if (list) {
        // The authenticated user is the list owner and can therefore delete task
        return true;
      } else {
        return false;
      }
    })
    .then((canDeleteTask) => {
      if (canDeleteTask) {
        Task.findOneAndRemove({
          _id: req.params.taskId,
          _listId: req.params.listId,
        })
          .then((removedTaskDoc) => {
            res.send(removedTaskDoc);
          })
          .catch((e) => {
            res.send(e);
          });
      } else {
        res.sendStatus(404);
      }
    });
});

// USER ROUTES

// POST /users
// Purpose: Sign up
app.post("/users", (req, res) => {
  // User sign up
  let body = req.body;
  let newUser = new User(body);

  newUser
    .save()
    .then(() => {
      return newUser.createSession();
    })
    .then((refreshToken) => {
      // Session created successfully - refresh token returned
      // Generate an access auth token for the user
      return newUser
        .generateAccessAuthToken()
        .then((accessToken) => {
          // Access token generated successfully, return an object containing the auth tokens
          return { accessToken, refreshToken };
        })
        .then((authToken) => {
          // Send the token and newuser to the user
          res
            .header("x-refresh-token", authToken.accessToken)
            .header("x-access-token", authToken.accessToken)
            .send(newUser);
        })
        .catch((e) => {
          res.status(400).send(e);
        });
    });
});

// POST /users/login
// Purpose: Login
app.post("/users/login", (req, res) => {
  let email = req.body.email;
  let password = req.body.password;
  User.findByCredentials(email, password)
    .then((user) => {
      return user
        .createSession()
        .then((refreshToken) => {
          // Session created successfully - refresh token returned
          // Generate the access auth token
          return user.generateAccessAuthToken().then((accessToken) => {
            // Access token generated successfully, return an object containing the auth tokens
            return { accessToken, refreshToken };
          });
        })
        .then((authToken) => {
          // Send the token and newuser to the user
          res
            .header("x-refresh-token", authToken.refreshToken)
            .header("x-access-token", authToken.accessToken)
            .send(user);
        });
    })
    .catch((e) => {
      res.status(400).send(e);
    });
});

// Get /me/access-token
// Purpose: Get Access Token
app.get("/users/me/access-token", verifySession, (req, res) => {
  // We know the user is authenticated and we have the user id and user object available to us from the middleware
  req.userObject
    .generateAccessAuthToken()
    .then((accessToken) => {
      res.header("x-access-token", accessToken).send([accessToken]);
    })
    .catch((e) => {
      res.status(400).send(e);
    });
});

/* HELPER METHODS */
let deleteTaskFromList = (_listId) => {
  Task.deleteMany({ _listId }).then(() => {
    console.log(`Tasks in ${_listId} were deleted`);
  });
};

app.listen(3000, () => {
  console.log("Server is listening on port 3000");
});
