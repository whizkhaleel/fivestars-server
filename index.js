const express = require("express");
const cors = require("cors");
const body_parser = require("body-parser");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const jwt = require("jsonwebtoken");
const ObjectId = require("mongodb").ObjectId;

const app = express();
app.use(
  cors({
    origin: "http://localhost:3000",
  })
);
app.use(body_parser.json());

const { MongoClient, ObjectID } = require("mongodb");

const URI =
  "mongodb+srv://fivestarsds:Gwandu1122@cluster0.mccdvlg.mongodb.net/?retryWrites=true&w=majority";

app.post("/api/register", async (req, res) => {
  const client = new MongoClient(URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  try {
    await client.connect();
    const database = client.db("vtu_db");
    const collection = database.collection("users");

    const { firstname, lastname, email, phone, username, password } = req.body;

    const saltRounds = 10;
    const salt = await bcrypt.genSalt(saltRounds);
    const hashedPassword = await bcrypt.hash(password, salt);

    const existingUser = await collection.findOne({
      $or: [{ username: username }, { phone_no: phone }, { email: email }],
    });

    if (existingUser) {
      res.json({
        message: "Username, Phone, or Email already exist.",
        error: "User already registered",
      });
      return;
    }

    const newUser = {
      f_name: firstname,
      l_name: lastname,
      email: email,
      phone_no: phone,
      username: username,
      password: hashedPassword,
      salt: salt,
      user_role: "2",
      date_created: Date(),
    };

    const result = await collection.insertOne(newUser);

    if (result) {
      res.status(201).json({ message: "Your registration is successful" });
    } else {
      res.status(500).json({ error: "Internal server error" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  } finally {
    await client.close();
  }
});

app.post("/api/login", async (req, res) => {
  const client = new MongoClient(URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  try {
    await client.connect();
    const database = client.db("vtu_db");
    const collection = database.collection("users");

    const { username, password } = req.body;

    const user = await collection.findOne({ username: username });

    if (!user) {
      res.json({
        message: "Invalid Login credentials!",
      });
      return;
    }

    const storedHashedPassword = user.password;
    const storedSalt = user.salt;
    const hashedEnteredPassword = await bcrypt.hash(password, storedSalt);
    const isPasswordMatch = hashedEnteredPassword === storedHashedPassword;

    if (isPasswordMatch) {
      const secretKey = crypto.randomBytes(32).toString("hex");
      const payload = {
        userID: user._id,
        userRole: user.user_role,
      };
      const expiration = Math.floor(Date.now() / 1000) + 30 * 60;
      const token = jwt.sign(payload, secretKey, {
        expiresIn: expiration,
      });

      res.status(201).json({ message: "Login successful!", token });
    } else {
      res.json({
        message: "Invalid Login credentials!",
      });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal server error." });
  } finally {
    await client.close();
  }
});

app.post("/api/user/:userID", async (req, res) => {
  const userID = req.params.userID;

  const client = new MongoClient(URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });

  try {
    await client.connect();
    const database = client.db("vtu_db");
    const collection = database.collection("users");

    const user = await collection.findOne({
      _id: new ObjectId(userID),
    });

    if (user) {
      res.status(201).json({
        user_id: user._id,
        f_name: user.f_name,
        l_name: user.l_name,
      });
    } else {
      res.status(404).json({ message: "No user found" });
    }
  } catch (err) {
    console.error(err);
    res.status(500).json({ message: "Internal Server Error" });
  } finally {
    await client.close();
  }
});

app.set("port", 3001);
app.listen(3001, () => {
  console.log("Server is running on port 3001");
});
