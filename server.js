const express = require("express");
const app = express();
const port = 3000;
const bodyParser = require("body-parser");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const { response } = require("express");

const data = {
  users: [
    // {
    //   id: "",
    //   firstName: "",
    //   lastName: "",
    // },
  ],
  messages: [
    // {
    //   id: "",
    //   authorId: "",
    //   authorName: "",
    //   timestamp: "",
    //   content: "",
    // },
  ],
};

function checkUserId(userId) {
  for (let i = 0; i < data.users.length; i++) {
    if (data.users[i].id === userId) {
      return true;
    }
  }
  return false;
}

function checkAuthorizationHeader(req) {
  const authorizationHeader = req.headers.authorization;
  return authorizationHeader;
}

app.use(bodyParser.json());
app.use(
  cors({
    origin: "*",
  })
);

app.get("/user", (req, res) => {
  const userId = req.query.id;
  if (userId) {
    const user = data.users.find((u) => u && u.id === userId);
    if (user && user.id) {
      res.json(user);
      return;
    }
  }

  res.sendStatus(404);
});

app.get("/messages", (req, res) => {
  const idFRomAuthorization = checkAuthorizationHeader(req);
  console.log("authorizationHeader", idFRomAuthorization);

  if (idFRomAuthorization) {
    const userAuthorized = checkUserId(idFRomAuthorization);
    if (userAuthorized) {
      return res.json(data.messages);
    }
  }
  res.status(401).send("Authorization required");
});

app.put("/user", (req, res) => {
  data.user = {
    id: "",
    firstName: req.body.firstName,
    lastName: req.body.lastName,
  };

  res.json(data.user);
});

app.delete("/user", (req, res) => {
  const userId = req.query.id;

  if (userId) {
    const userIndex = data.users.findIndex((u) => u && u.id === userId);
    if (userIndex > -1) {
      data.users.splice(userIndex, 1);
      res.status(200).send("User was signed out successfully");
      return;
    }
  }
  res.sendStatus(404);
});

app.delete("/messages", (req, res) => {
  data.messages.splice(0, data.messages.length);
  res.status(200).send("OK");
});

app.post("/user", (req, res) => {
  const id = uuidv4();

  const user = {
    id: id,
    firstName: req.body.firstName,
    lastName: req.body.lastName,
  };
  data.users.push(user);
  res.send(user);
});

app.post("/messages", (req, res) => {
  const idFRomAuthorization = checkAuthorizationHeader(req);
  if (idFRomAuthorization) {
    const userAuthorized = checkUserId(idFRomAuthorization);
    if (userAuthorized) {
      if (
        !req.body.authorId ||
        !req.body.authorName ||
        !req.body.timestamp ||
        !req.body.content
      ) {
        res.status(400).send("Body needed");
        return;
      }
      const messageId = uuidv4();
      const message = {
        id: messageId,
        authorId: req.body.authorId,
        authorName: req.body.authorName,
        timestamp: req.body.timestamp,
        content: req.body.content,
      };
      data.messages.push(message);

      res.status(200).send("OK");
    }
  }
  res.status(401).send("Authorization required");
  // return res.json(data.messages);
});

app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});
