const express = require("express");
const session = require('express-session')
const fs = require("fs");
const bcrypt = require("bcrypt");


const app = express();
//Constants
const FILE_NAME = "users.json";

//Middleware
app.use(express.json());
app.use(express.urlencoded({extended:false}));
app.use(session({
    name:"session",
    secret: 'secret',
    resave: false,
    saveUninitialized:true
}));

let usersText = fs.readFileSync(FILE_NAME,"utf-8");
const users = JSON.parse(usersText);

app.get("/",checkNoAuth,(req, res) =>{
    res.sendFile(__dirname + "/front-end/index.html");
})

app.get("/reg",checkAuth, (req, res) => {
    res.sendFile(__dirname + "/front-end/reg.html");
})

app.post("/reg", checkAuth, async (req, res) =>{
    if(!(req.body.un && req.body.pw)){
        res.status(400).send();
    }
    else if(findUNIndex(users,req.body) != -1){
        res.send("Username is already registered!");
    }
    else{
        let salt = await bcrypt.genSalt(10);
        let hash = await bcrypt.hash(req.body.pw + "", salt); 
        let user = {un:req.body.un,pw:hash};        
        users.push(user);
        addToJSON();
        res.send("successfully registered!");
    }
    console.log(users)
})
app.get("/login",checkAuth, (req, res) => {
    res.sendFile(__dirname + "/front-end/log.html");
})
app.post("/login",checkAuth, async (req, res) => {
    if(!(req.body.un && req.body.pw)){
        res.status(400).send();
    } 
    else{
        let i = findUNIndex(users,req.body)
        console.log(i);
        if(i != -1){
            let same = await bcrypt.compare(req.body.pw+"",users[i].pw);
            if(same){
                req.session.un = req.body.un;
                res.redirect("/");
            }
            else{
                res.send("<h1>Wrong password!</h1>");
                res.end();
            }
        }
        else{
            res.send("failed");
        }
        
    }
});
app.post("/logout",checkNoAuth,function(req,res){
    req.session.destroy((err) => {
        if (err) res.redirect("/");
        res.clearCookie("session");
        return res.redirect("/login");
    });

})

app.listen(3000,() =>{
    console.log("Listening in 3000!");
})

function addToJSON(){
    fs.writeFile(FILE_NAME,JSON.stringify(users), function(err){
        if(err) throw err;
    })
}

function findUNIndex(users, user){
    for(let i = 0 ; i < users.length; i++){
        if(users[i].un == user.un){
            return i;
        }
    }
    return -1;
}

function checkAuth(req,res,next){
    console.log(req.session.un);
    console.log(next);
    if(req.session.un){
        res.redirect("/");  
    }else{
        console.log("next working!");
        next();
    }
}

function checkNoAuth(req,res,next){
    console.log(req.session.un);
    if(req.session.un){
        next();
    }
    else{
        res.redirect("/login");
    }
}