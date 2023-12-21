//---------REMEMBER IF BY STARTING THE PROJECT YOU GET A REGENERATE ERROR, UNINSTALL PASSPORT@0.5 AND RE-INSTALL PASSPORT

require("dotenv").config();
const https = require("https");
const fs = require("fs");
const path = require("path");
const helmet = require("helmet");
const passport = require("passport");
const { Strategy } = require("passport-google-oauth20");
const cookieSession = require("cookie-session");
const express = require("express");

const PORT = 3000;

const config = {
  CLIENT_ID: process.env.CLIENT_ID,
  CLIENT_SECRET: process.env.CLIENT_SECRET,
  COOKIE_KEY_1: process.env.COOKIE_KEY_1,
  COOKIE_KEY_2: process.env.COOKIE_KEY_2,
};

const AUTH_OPTIONS = {
  callbackURL: "/auth/google/callback",
  clientID: config.CLIENT_ID,
  clientSecret: config.CLIENT_SECRET,
};

//accessToken is the token provided for logging in succesfully
//refreshToken is the extension of the expiray date of the accessToken so that the token still remains
function verifyCallback(accessToken, refreshToken, profile, done) {
  console.log("google profile", profile);
  //after successfully logging in it will get the profile or else a null value
  done(null, profile);
}

passport.use(new Strategy(AUTH_OPTIONS, verifyCallback));

//Save the session to cookie
//it takes a callback and is executed whenever the user is being saved to the cookie to be sent back to the browser
//it takes the user and done to tell it is done
passport.serializeUser((user, done) => {
  //We are just going to use user id to minimize the size of the data sent by the cookie
  //cookies can store upto 4kb
  done(null, user.id);
});

//Read the session from the cookie
passport.deserializeUser((id, done) => {
  done(null, id);
});

const app = express();

// Helmet helps you secure your Express apps by setting various HTTP headers.
//basically when we dont use helmet, in our network tab inside our headers section.. it shows X-powered by:Express
//it tells that it is made by express, but after using helmet it hides all our headers...
app.use(helmet());

app.use(
  cookieSession({
    name: "session",
    //for 1 day
    maxAge: 24 * 60 * 60 * 1000,
    //list of secret values used to keep cookies secure
    //helps in preventing user modifying cookie(for eg. modifying their details to be looking as another user)
    keys: [config.COOKIE_KEY_1, config.COOKIE_KEY_2],
  })
);

//Middleware to setup passport
app.use(passport.initialize());

//authenticates the session sent to our server
app.use(passport.session());

//middleware function that checks whether the user is logged in or not
function checkLoggedIn(req, res, next) {
  console.log("current user is:", req.user);
  //isAuthenticated to check whether passport found a user in the session and user property libves in our request
  const isLoggedIn = req.isAuthenticated() && req.user;
  if (!isLoggedIn) {
    return res.status(401).json({
      error: "Login Please",
    });
  }
  next();
}

app.get(
  "/auth/google",
  passport.authenticate("google", {
    //scope specifies which data we are requesting from google when everything succeeds
    scope: ["email"],
  })
);

app.get(
  "/auth/google/callback",
  passport.authenticate("google", {
    failureRedirect: "/failure",
    successRedirect: "/",
    session: true,
  }),
  (req, res) => {
    console.log("Google Called us!");
  }
);

app.get("/auth/logout", (req, res) => {
  //Removes req.user and clears any loggedIn session
  req.logOut();
  return res.redirect("/");
});

app.get("/secret", checkLoggedIn, (req, res) => {
  return res.send("Your personal secret value is 42");
});

app.get("/failure", (req, res) => {
  return res.send("Failed to lof in!");
});

app.get("/", (req, res) => {
  res.sendFile(path.join(__dirname, "public", "index.html"));
});

https
  .createServer(
    {
      //to load those files first before passing them as key
      key: fs.readFileSync("key.pem"),
      cert: fs.readFileSync("cert.pem"),
    },
    app
  )
  .listen(PORT, () => {
    console.log(`Listening on port ${PORT}...`);
  });
