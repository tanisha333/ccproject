require("dotenv").config();

const express = require("express");
const mongoose = require("mongoose");
const jwt = require("jsonwebtoken");
const bodyParser = require("body-parser");

const passport = require("passport");
const GoogleStrategy = require("passport-google-oauth20").Strategy;

const app = express();

app.use(bodyParser.json());
app.use(express.static("public"));

const SECRET = "supersecret";

// ==========================
// 🌐 MONGODB CONNECTION
// ==========================
const MONGO_URL = process.env.MONGO_URL;

mongoose.connect(MONGO_URL)
.then(()=>console.log("✅ MongoDB Connected"))
.catch(err=>console.log(err));

// ==========================
// 📦 USER MODEL
// ==========================
const User = mongoose.model("User",{
  email:String,
  password:String
});

// ==========================
// 🔐 SIGNUP
// ==========================
app.post("/signup", async (req,res)=>{
  const {email,password} = req.body;

  if(!email || !password) return res.send("Missing fields");

  const existing = await User.findOne({email});
  if(existing) return res.send("User already exists");

  await User.create({email,password}); // (later: hash with bcrypt)
  res.send("Signup successful");
});
// ==========================
// 🔐 LOGIN (EMAIL)
// ==========================
app.post("/login", async (req,res)=>{
  const {email,password} = req.body;

  const user = await User.findOne({email,password});

  if(!user) return res.send({success:false});

  const token = jwt.sign({email}, SECRET, {expiresIn:"1d"});

  res.send({success:true, token});
});

// ==========================
// 🌍 GOOGLE AUTH (NO SESSION)
// ==========================
app.use(passport.initialize());

passport.use(new GoogleStrategy({
  clientID:process.env.GOOGLE_CLIENT_ID,
  clientSecret: process.env.GOOGLE_CLIENT_SECRET,
  callbackURL:process.env.GOOGLE_CALLBACK_URL
},
async (accessToken, refreshToken, profile, done)=>{

  const email = profile.emails[0].value;

  let user = await User.findOne({email});

  if(!user){
    user = await User.create({
      email,
      password:"google"
    });
  }

  return done(null,{email});
}));

// ==========================
// 🔗 GOOGLE ROUTES
// ==========================
app.get("/auth/google",
passport.authenticate("google",{
  scope:["profile","email"],
  session:false
}));

app.get("/auth/google/callback",
passport.authenticate("google",{
  failureRedirect:"/",
  session:false
}),
(req,res)=>{

  const token = jwt.sign(
    {email:req.user.email},
    SECRET,
    {expiresIn:"1d"}
  );

  res.redirect(`/homepage.html?token=${token}`);
});

// ==========================
// 🔐 VERIFY TOKEN (SSO)
// ==========================
app.get("/verify",(req,res)=>{
  const token = req.headers.authorization;

  if(!token) return res.send(null);

  try{
    const data = jwt.verify(token, SECRET);
    res.send(data);
  }catch{
    res.send(null);
  }
});

// ==========================
// 🚀 START SERVER
// ==========================
app.listen(3000,()=>{
  console.log("🚀 Server running on port 3000");
});
