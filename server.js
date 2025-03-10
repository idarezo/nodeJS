const express = require("express");
const https = require("node:https");
const path = require("path");
const fs = require("fs");
const axios = require("axios");
const { body, validationResult } = require("express-validator");
const mongoose = require("mongoose");
const bcrypt = require("bcryptjs");
const rateLimit = require("express-rate-limit");
require("dotenv").config();
const jwt = require("jsonwebtoken");

mongoose
  .connect("mongodb://localhost:27017/DIplomska", {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  })
  .then(() => console.log("Connected to MongoDB"))
  .catch((err) => console.error("Failed to connect to MongoDB", err));

const privateKey = fs.readFileSync(
  "C:/Users/991460/Desktop/Diplomska/certifikati/server.key",
  "utf8"
);
const certificate = fs.readFileSync(
  "C:/Users/991460/Desktop/Diplomska/certifikati/server.crt",
  "utf8"
);

const ca = fs.readFileSync(
  "C:/Users/991460/Desktop/Diplomska/certifikati/server.crt",
  "utf8"
);

const credentials = {
  key: privateKey,
  cert: certificate,
  ca: ca,
  passphrase: "r1963b",
};

const app = express();
const port = 3000;
const bodyParser = require("body-parser");
const cors = require("cors");
const { v4: uuidv4 } = require("uuid");
const { response } = require("express");
const jwtSecret = process.env.JWT_SECRET;

//Sheme podatkov na bazi
const userSchema = new mongoose.Schema({
  uuid: { type: String, required: true, unique: true },
  firstName: { type: String, required: true },
  lastName: { type: String, required: true },
  email: { type: String, required: true, unique: true },
  password: { type: String, required: true },
  phoneNumber: { type: String, default: "" },
  gender: { type: String, default: null },
  role: {
    type: String,
    enum: ["user", "admin"],
    default: "user",
  },
});
const messageSchema = new mongoose.Schema({
  authorId: { type: String, required: true },
  authorEmail: { type: String, required: true },
  authorName: { type: String, required: true },
  timestamp: { type: String, required: true },
  content: { type: String, required: true },
});

//Omejevalnika
const loginLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 70,
  message: "Preveč prijavnih poskusov. Poskusite znova čez 1 minuto.",
  statusCode: 429,
  standardHeaders: true,
  legacyHeaders: false,
  keyGenerator: (req) => req.body.emailValue || req.ip,
  handler: (req, res, next, options) => {
    console.warn(`Rate limit dosežen za: ${req.ip}`);
    res.status(options.statusCode).json({
      error: options.message,
      retryAfter: options.windowMs / 1000 + " sekund",
    });
  },
});

const generalLimiter = rateLimit({
  windowMs: 1 * 60 * 1000,
  max: 100,
  message: "Prevec zahtevkov. Pocakajte 1 minuto.",
  statusCode: 429,
  standardHeaders: true,
  legacyHeaders: false,
  skipFailedRequests: true,
});

const User = mongoose.model("User", userSchema);
const Message = mongoose.model("Message", messageSchema);

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

//Funkcija za generiranje zetonov
function generateToken(user) {
  return jwt.sign(
    {
      uuid: user.uuid,
      email: user.email,
      role: user.role,
    },
    process.env.JWT_SECRET,
    { expiresIn: process.env.JWT_EXPIRES_IN }
  );
}

//Funkcije za preverjanje zetonov
function verifyToken(req, res, next) {
  const token = req.headers.authorization?.split(" ")[1];
  console.log("Authorization header token trimmed:", token);

  if (!token) {
    return res.status(401).json({ message: "Authorization token required" });
  }

  try {
    const decoded = jwt.verify(token, process.env.JWT_SECRET);
    req.user = decoded;
    next();
  } catch (err) {
    console.log("ERROR");
    return res.status(401).json({ message: "Invalid or expired token" });
  }
}

function checkRoleAdmin(role) {
  return function (req, res, next) {
    if (req.user.role.includes(role)) {
      next();
    } else {
      res.status(403).send("Dostop zavrnjen.");
    }
  };
}
function checkRoleUser() {
  return (req, res, next) => {
    if (!req.user) {
      return res.status(401).json({ message: "Authorization required" });
    }
    if (req.user.role === "user" || req.user.role === "admin") {
      next();
    } else {
      res.status(403).json({ message: "Access denied" });
    }
  };
}

const permissions = {
  user: [
    "GET:/userInfo",
    "PUT:/userInfo",
    "GET:/messages",
    "POST:/postMessage",
  ],
  admin: ["GET:/allUsers", "DELETE:/usersDelete", "GET:/messages"],
};

function hasPermission(role, method, path) {
  const permission = `${method}:${path}`;
  return permissions[role]?.includes(permission);
}

function checkPermissions(role) {
  return (req, res, next) => {
    if (hasPermission(role, req.method, req.path)) {
      next();
    } else {
      return res.status(403).json({ message: "Access denied" });
    }
  };
}

function updateProfile(newUser, oldUser) {}
//MiddleWare
app.use(bodyParser.json());

app.use(
  cors({
    origin: "*",
  })
);
app.use("/userLogin", loginLimiter);
app.use("/userRegistracija", loginLimiter);
app.use(generalLimiter);

//Pridobivanje slik na podlagi URL naslova
app.get("/fetchImage", async (req, res) => {
  const targetUrl = req.query.url;

  if (!targetUrl) {
    return res.status(400).json({ error: "'url' parameter is required" });
  }

  try {
    // Pošljemo zahtevo pomočnemu strežniku za pridobitev slike
    const response = await axios.get(
      `http://localhost:3001/fetchFromExternal?url=${encodeURIComponent(
        targetUrl
      )}`,
      { responseType: "stream" }
    );
    if (res.status == "400") {
      res.status(400).json({
        error: "Private IP address detected. Forbidden.",
      });
    }
    if (res.status == "500") {
      res.status(400).json({
        error: "Private IP address detected. Forbidden.",
      });
    }

    res.setHeader("Content-Type", response.headers["content-type"]);
    res.setHeader("Content-Length", response.headers["content-length"]);
    response.data.pipe(res);
  } catch (error) {
    res.status(500).json({
      error: "Error when calling the secondary server.",
      details: error.message,
    });
  }
});

//Pidobivanje podatkov za prikaz osebnega profila

app.get(
  "/userInfo",
  verifyToken,
  checkPermissions("user"),
  async (req, res) => {
    const userUuid = req.user.uuid;

    if (!userUuid) {
      return res.status(400).send("User UUID required");
    }

    try {
      const user = await User.findOne({ uuid: userUuid });
      if (user) {
        console.log("NAJDENI UPORABNIK");
        return res.status(200).json({
          success: true,
          message: "Login successful",
          user,
        });
      } else {
        return res.status(404).json({
          success: false,
          message: "User not found",
        });
      }
    } catch (err) {
      console.error("Error retrieving user:", err);
      return res.status(500).json({
        success: false,
        message: "Error retrieving user from the database",
      });
    }
  }
);

app.put(
  "/userInfo/:idProfile",
  [
    body("firstName").isString().trim().escape(),
    body("lastName").isString().trim().escape(),
    body("email").isEmail().normalizeEmail(),
    body("gender").isIn(["male", "female", "other"]).optional(),
    body("password").optional().isLength({ min: 6 }),
  ],
  verifyToken,
  checkPermissions("user"),
  async (req, res) => {
    const { idProfile } = req.params;
    const updatedProfle = req.body;

    // Preverjanje lastništva profila
    if (idProfile !== req.user.uuid) {
      return res
        .status(403)
        .json({ message: "Not authorized to update this profile" });
    }

    try {
      const user = await User.findOne({ uuid: idProfile });
      if (!user) {
        return res.status(404).json({ message: "User not found" });
      }

      const allowedUpdates = [
        "firstName",
        "lastName",
        "email",
        "gender",
        "password",
      ];
      Object.keys(updatedProfle).forEach((key) => {
        if (allowedUpdates.includes(key)) {
          if (key === "password" && updatedProfle[key]) {
            bcrypt.hash(updatedProfle[key], 10, (err, hashedPassword) => {
              if (err) {
                return res.status(500).json({ message: "Password hash error" });
              }
              user.password = hashedPassword;
              user.save();
            });
          } else {
            user[key] = updatedProfle[key];
          }
        }
      });

      await user.save();
      res.json({ message: `Profile ${user._id} updated successfully!`, user });
    } catch (error) {
      console.error("Error updating profile:", error);
      res
        .status(500)
        .json({ message: "Failed to update profile", error: error.message });
    }
  }
);

//Končna točka namenjena administratorju
app.delete(
  "/usersDelete/:id",
  verifyToken,
  checkPermissions("admin"),
  async (req, res) => {
    const userId = req.params.id;
    if (!userId) {
      return res
        .status(400)
        .json({ success: false, message: "Manjka ID uporabnika" });
    }
    try {
      const deletedUser = await User.findOneAndDelete({ uuid: userId });

      if (!deletedUser) {
        return res
          .status(404)
          .json({ success: false, message: "Uporabnik ni bil najden" });
      }

      res.json({ success: true, message: `Uporabnik ${userId} izbrisan` });
    } catch (err) {
      console.error("Napaka pri brisanju:", err);
      res
        .status(500)
        .json({ success: false, message: "Napaka pri brisanju uporabnika" });
    }
  }
);

//Pridobitev uporabnikov iz baze
app.get(
  "/allUsers",
  verifyToken,
  checkPermissions("admin"),
  async (req, res) => {
    try {
      console.log("ALLUsers endpoint called");
      console.log(req.headers.authorization);

      const users = await User.find();
      if (users.length > 0) {
        res.json({
          success: true,
          message: "Login successful",
          token: req.headers.authorization?.split(" ")[1],
          users,
        });
      } else {
        return res.status(404).send("No users found");
      }
    } catch (error) {
      console.error("Error fetching users:", error);
      return res.status(500).send("Internal server error");
    }
  }
);
//1. metoda klicana
app.get("/user", verifyToken, checkPermissions("user"), async (req, res) => {
  console.log("GET /user called");

  const userUuid = req.query.uuid;

  if (!userUuid) {
    return res.status(400).send("User UUID required");
  }

  try {
    const user = await User.findOne({ uuid: userUuid });

    if (user) {
      console.log("NAJDENI UPORABNIK");
      return res.json(user);
    } else {
      return res.status(404).send("User not found");
    }
  } catch (err) {
    console.error("Error retrieving user:", err);
    return res.status(500).send("Error retrieving user from the database"); // Catch any other errors
  }
});

//Dodajanje sporocil
//uspesno dodajanje sporocil na bazo
app.post(
  "/postMessage",
  verifyToken,
  checkPermissions("user"),
  async (req, res) => {
    console.log("postMessage /postMessage called");
    console.log(req.body);

    const { authorId, authorEmail, authorName, timestamp, content } = req.body;

    if (!authorName || !timestamp || !content) {
      return res.status(400).json({ error: "Missing required fields" });
    }

    const newMessage = new Message({
      authorId,
      authorEmail,
      authorName,
      timestamp,
      content,
    });

    try {
      await newMessage.save();
      res.status(201).json(newMessage);
    } catch (error) {
      console.error("Error saving message:", error);
      res.status(500).json({ error: "Failed to save message" });
    }
  }
);

//novi get user
// delujoca prijava / logIn
app.post("/userLogin", async (req, res) => {
  console.log("POST /userLogin called");
  console.log("JWT_SECRET:", process.env.JWT_SECRET);
  console.log(req.body);

  const email = req.body.emailValue;
  const pswd = req.body.psw;

  if (!email || !pswd) {
    return res.status(400).send("Email and password are required");
  }

  try {
    const user = await User.findOne({ email });

    if (!user) {
      return res.status(404).send("User not found. Enter a valid email");
    }

    const isMatch = await bcrypt.compare(pswd, user.password);
    if (!isMatch) {
      return res.status(401).send("Incorrect password");
    }

    console.log("User authenticated successfully");
    const token = generateToken(user);
    res.json({
      success: true,
      message: "Login successful",
      token,
      user: {
        _id: user.uuid,
        email: user.email,
        firstName: user.firstName,
        lastName: user.lastName,
        role: user.role,
      },
    });
  } catch (err) {
    console.error("Error retrieving user:", err);
    res.status(500).send("Error retrieving user from the database");
  }
});

//3. metoda klicana
// delujoce pridobivanje sporocil
app.get(
  "/messages",
  verifyToken,
  checkPermissions("user"),
  async (req, res) => {
    console.log("GET /messages called");
    const idFromAuthorization = checkAuthorizationHeader(req);

    if (idFromAuthorization) {
      try {
        const messages = await Message.find();
        if (messages.length > 0) {
          console.log();
          return res.json(messages);
        } else {
          return res.status(404).send("No messages found");
        }
      } catch (error) {
        console.error("Error fetching messages:", error);
        return res.status(500).send("Internal server error");
      }
    }

    res.status(401).send("Authorization required");
  }
);

//2. metoda klicana
//uspesna registracija uporabnika
app.post("/userRegistracija", async (req, res) => {
  console.log("POST /userRegistracija called");
  console.log("Received body:", req.body);

  const salt = await bcrypt.genSalt(10);
  const hashedPassword = await bcrypt.hash(req.body.psw, salt);

  try {
    const newUser = new User({
      uuid: uuidv4(),
      firstName: req.body.firstName,
      lastName: req.body.lastName,
      email: req.body.emailValue,
      password: hashedPassword,
      phoneNumber: req.body.rojstniDan,
      gender: req.body.genderValue,
    });

    const existingUser = await User.findOne({ email: req.body.emailValue });
    if (existingUser) {
      return res
        .status(409)
        .send("User with this email already exists. Enter different email");
    } else {
      await newUser.save(); // Shrani uporabnika v MongoDB
      res.json({
        success: true,
        message: "Login successful",
        newUser,
      });
      // res.send(newUser);
    }
  } catch (err) {
    console.error("Error saving user:", err);
    res.status(500).send("Error saving user to the database");
  }
});
app.get("/", (req, res) => {
  res.send("Hello, world!");
});

/*app.listen(port, () => {
  console.log(`Example app listening on port ${port}`);
});*/

https.createServer(credentials, app).listen(3000, "0.0.0.0", () => {
  console.log("HTTPS strežnik teče na https://localhost:3000");
});
/*
CORS zaščita (npr. dovoljenje le določenim domenam),
Bolje definirane pravice uporabnikov (RBAC - Role Based Access Control).
Primerjava z realnimi napadi – ali imaš vire o dejanskih varnostnih incidentih povezanih z API-ji? Lahko vključiš primere znanih API ranljivosti iz OWASP poročil.
API7:2023 - Security Misconfiguration
Neomejen CORS (*) odpira vrata cross-origin napadom, kjer napadalci lahko berejo podatke iz API-ja brez ustreznega dovoljenja.
*/
