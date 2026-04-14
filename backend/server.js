const express = require("express");
const cors = require("cors");
const jwt = require("jsonwebtoken");
const sqlite3 = require("sqlite3").verbose();

const app = express();
app.use(cors({ origin: "*" }));
app.use(express.json());

const SECRET = process.env.SECRET || "secret_key";

// DB
const db = new sqlite3.Database("./db.sqlite");

db.run(`
CREATE TABLE IF NOT EXISTS users (
id INTEGER PRIMARY KEY AUTOINCREMENT,
email TEXT UNIQUE,
password TEXT,
sub TEXT DEFAULT 'inactive',
role TEXT DEFAULT 'user'
)
`);

// AUTH
function auth(req,res,next){
const token = req.headers.authorization;
if(!token) return res.sendStatus(401);

try{
req.user = jwt.verify(token, SECRET);
next();
}catch{
res.sendStatus(403);
}
}

// REGISTER
app.post("/register",(req,res)=>{
db.run(
"INSERT INTO users(email,password) VALUES(?,?)",
[req.body.email,req.body.password],
(err)=>{
if(err) return res.json({ok:false});
res.json({ok:true});
}
);
});

// LOGIN
app.post("/login",(req,res)=>{
db.get(
"SELECT * FROM users WHERE email=? AND password=?",
[req.body.email,req.body.password],
(err,user)=>{
if(!user) return res.json({ok:false});

const token = jwt.sign(
{email:user.email, role:user.role},
SECRET,
{expiresIn:"7d"}
);

res.json({ok:true, token});
}
);
});

// ME
app.get("/me",auth,(req,res)=>{
db.get(
"SELECT email,sub,role FROM users WHERE email=?",
[req.user.email],
(err,user)=>{
res.json(user);
}
);
});

// PAY (stub)
app.post("/pay",auth,(req,res)=>{
res.json({url:"https://platega.io/pay-demo"});
});

// ADMIN USERS
app.get("/admin-users",auth,(req,res)=>{
if(req.user.role !== "admin") return res.sendStatus(403);

db.all("SELECT email,sub,role FROM users",(e,rows)=>{
res.json(rows);
});
});

// GIVE SUB
app.post("/give-sub",auth,(req,res)=>{
if(req.user.role !== "admin") return res.sendStatus(403);

db.run(
"UPDATE users SET sub='active' WHERE email=?",
[req.body.email]
);

res.json({ok:true});
});

app.listen(3000,()=>console.log("SERVER RUN"));
