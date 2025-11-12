require("dotenv").config()
const sanitizeHTML=require('sanitize-html')
const express = require("express")
const db=require("better-sqlite3")("ourApp.db")
const bcrypt=require("bcrypt")
const cookieParser=require('cookie-parser')
const jwt= require("jsonwebtoken")
db.pragma("journal_mode=WAL")

//database setup here

const createTables=db.transaction(() => {
    db.prepare(`
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
        `).run()

        db.prepare(`
            CREATE TABLE IF NOT EXISTS posts (id INTEGER PRIMARY KEY AUTOINCREMENT,
            createdDate TEXT,
            rideTo TEXT NOT NULL,
            rideFrom TEXT NOT NULL,
            rideDate TEXT NOT NULL,
            rideTime TEXT NOT NULL,
            fare FLOAT NOT NULL,
            authorid INTEGER,
            FOREIGN KEY (authorid) REFERENCES users (id)
            )
            `).run()
})

createTables()

//database setup ends here

const app = express()

app.set ("view engine", "ejs")
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"))
app.use(cookieParser())

app.use(function (req, res, next) {
    res.locals.errors = []

    //try to decode incoming cookie

    try{
        const decoded = jwt.verify(req.cookies.ourSimpleApp, process.env.JWTSECRET)
        req.user = decoded
    } catch(err){
        req.user = false
    }

    res.locals.user=req.user
    console.log(req.user)
    next()
})

app.get("/", (req, res) => {
    if (req.user) {
        const postsStatement=db.prepare("SELECT * FROM posts WHERE authorid=?")
        const posts=postsStatement.all(req.user.userid)
       return res.render("dashboard", {posts})
    }    
    res.render("homepage")
})

app.get("/login", (req, res) => {
    res.render("login")
})

app.get("/logout", (req,res) => {
    res.clearCookie("ourSimpleApp")
    res.redirect("/")
})

app.post("/login", (req,res) =>{
   let errors = []

    if (typeof req.body.username !== "string") req.body.username=""
    if (typeof req.body.password !== "string") req.body.password=""

    if (req.body.username.trim() == "") errors=["Invalid username/ password."]
    if (req.body.password == "") errors=["Invalid username/ password."]

    if (errors.length) {
        return res.render("login", {errors})
    }

    const userInQuestionStatement=db.prepare("SELECT * FROM users WHERE USERNAME= ?")
    const userInQuestion=userInQuestionStatement.get(req.body.username)

    if (!userInQuestion){
        errors=["Invalid username / password."]
        return res.render("login", {errors})
    }

    const matchOrNot=bcrypt.compareSync(req.body.password, userInQuestion.password)
    if (!matchOrNot) {
        errors=["Invalid username / password."]
        return res.render("login", {errors})        
    }

    const ourToken=jwt.sign({exp: Math.floor(Date.now()/ 1000) + 60 * 60 * 24, skyColor: "blue", userid: userInQuestion.id, username: userInQuestion.username}, process.env.JWTSECRET)

    res.cookie("ourSimpleApp",ourToken, {
        httpOnly: true,
        secure: false,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    res.redirect("/")
})

function formatRideDateTime(rideDate, rideTime, req){  

    const dateObj = new Date(rideDate + "T" + rideTime);
    const formattedDate = `${dateObj.getMonth() + 1}/${dateObj.getDate()}/${dateObj.getFullYear()}`;
    
    let hours = dateObj.getHours();
    const minutes = dateObj.getMinutes().toString().padStart(2, "0");
    const ampm = hours >= 12 ? "PM" : "AM";
    hours = hours % 12 || 12;
    const formattedTime = `${hours}:${minutes} ${ampm}`;  

    return { formattedDate, formattedTime, dateObj };    
}
function mustBeLoggedIn(req, res, next){
    if (req.user){
        return next()
    }
    return res.redirect("/")
}

app.get("/create-post", mustBeLoggedIn, (req,res)=>{
    res.render("create-post")
})

function sharedPostValidation(req){
    const errors=[]
    if (typeof req.body.rideTo !== "string") req.body.rideTo=""
    if (typeof req.body.rideFrom !== "string") req.body.rideFrom=""
    if (typeof req.body.rideDate !== "string") req.body.rideDate=""
    if (typeof req.body.rideTime !== "string") req.body.rideTime=""
    if (typeof req.body.fare !== "string") req.body.fare=""

    //trim - sanitize or strip out html
    req.body.rideTo=sanitizeHTML(req.body.rideTo.trim(), {allowedTags: [], allowedAttributes: {}})
    req.body.rideFrom=sanitizeHTML(req.body.rideFrom.trim(), {allowedTags: [], allowedAttributes: {}})
    req.body.rideDate=sanitizeHTML(req.body.rideDate.trim(), {allowedTags: [], allowedAttributes: {}})
    req.body.rideTime=sanitizeHTML(req.body.rideTime.trim(), {allowedTags: [], allowedAttributes: {}})
    req.body.fare=sanitizeHTML(req.body.fare.trim(), {allowedTags: [], allowedAttributes: {}})
    
    
    if (!req.body.rideTo) errors.push("Must Provide Starting Location")
    if (!req.body.rideFrom) errors.push("Must Provide Destination")
    if (!req.body.rideDate) errors.push("Must Provide The Date For The Ride")
    if (!req.body.rideTime) errors.push("Must Provide The Time For The Ride")
    if (!req.body.fare) errors.push("Must Provide The Fare")
    
    //Fare Validation
    else if (isNaN(parseFloat(req.body.fare)) || parseFloat(req.body.fare) < 0) {
    errors.push("Fare must be a valid non-negative number.")}
   
    return errors
}   

app.get("/edit-post/:id", mustBeLoggedIn, (req, res)=>{
    //try to look up the post in question
    const statement=db.prepare("SELECT * FROM posts WHERE id=?")
    const post=statement.get(req.params.id)

    if (!post){
        return res.redirect("/")
    }

    //if you are not the author redirect to homepage
    if (post.authorid !== req.user.userid){
        return res.redirect("/")
    }

    //otherwise render edit template
    res.render("edit-post", {post})
})

app.post ("/edit-post/:id", mustBeLoggedIn, (req, res)=>{
    //try to look up the post in question
    const statement=db.prepare("SELECT * FROM posts WHERE id=?")
    const post=statement.get(req.params.id)

    if (!post){
        return res.redirect("/")
    }
    
    //if you are not the author redirect to homepage
    if (post.authorid !== req.user.userid){
        return res.redirect("/")
    }

    const errors=sharedPostValidation(req)
    const {formattedDate, formattedTime, dateObj} = formatRideDateTime(req.body.rideDate, req.body.rideTime);

    if (errors.length){
        return res.render("edit-post", {errors})
    }

    const updateStatement=db.prepare(`UPDATE posts
    SET rideTo=?, 
    rideFrom=?,
    rideDate=?,
    rideTime=?,
    fare=?
    WHERE id=?`)
    updateStatement.run(req.body.rideTo, req.body.rideFrom, formattedDate, formattedTime, parseFloat(req.body.fare), req.params.id)

    res.redirect(`/post/${req.params.id}`)

})

app.post("/delete-post/:id", mustBeLoggedIn,(req, res)=>{
    //try to look up the post in question
    const statement=db.prepare("SELECT * FROM posts WHERE id=?")
    const post=statement.get(req.params.id)

    if (!post){
        return res.redirect("/")
    }

    //if you are not the author redirect to homepage
    if (post.authorid !== req.user.userid){
        return res.redirect("/")
    }

    const deleteStatement=db.prepare("DELETE FROM posts WHERE id=?")
    deleteStatement.run(req.params.id)

    res.redirect("/")
})
app.get("/post/:id", (req,res)=>{
    const statement=db.prepare("SELECT posts.*, users.username FROM posts INNER JOIN users ON posts.authorid=users.id WHERE posts.id=?")
    const post=statement.get(req.params.id)

    if (!post){
        return res.redirect("/")
    }

    const isAuthor=post.authorid==req.user.userid
    res.render("single-post",{post, isAuthor})
})


app.post("/create-post",mustBeLoggedIn,(req, res)=>{
    const errors = sharedPostValidation(req)

    if (errors.length){
        return res.render("create-post", {errors})
    }

    const {formattedDate, formattedTime, dateObj} = formatRideDateTime(req.body.rideDate, req.body.rideTime);

    //save into database
    const ourStatement= db.prepare(" INSERT INTO posts (rideTo, rideFrom, rideDate, rideTime, fare, authorid, createdDate) VALUES (?, ?, ?, ?, ?, ?, ?)")
    const result=ourStatement.run(req.body.rideTo, req.body.rideFrom, formattedDate, formattedTime, parseFloat(req.body.fare), req.user.userid, new Date().toISOString())

    const getPostStatement= db.prepare("SELECT * FROM posts WHERE ROWID=?")
    const realPost=getPostStatement.get(result.lastInsertRowid)

    res.redirect(`/post/${realPost.id}`)
})

app.get("/find-ride", (req, res) => {
    const statement = db.prepare(`
        SELECT posts.*, users.username 
        FROM posts
        JOIN users ON posts.authorid = users.id
        ORDER BY datetime(posts.createdDate) DESC
    `)
    const posts = statement.all()

    res.render("find-ride", { posts })
})

app.post("/register", (req, res) =>{
    const errors = []

    if (typeof req.body.username !== "string") req.body.username=""
    if (typeof req.body.password !== "string") req.body.password=""

    req.body.username=req.body.username.trim()

    if (!req.body.username) errors.push("Please provide a username.")
    if (req.body.username && req.body.username.length < 3) errors.push("Username must be atleast 3 characters long")
    if (req.body.username && req.body.username.length > 10) errors.push("Username must be atmost 10 characters long")
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers")
    
   //check if username exists already
   const usernameStatement=db.prepare("SELECT * FROM users WHERE username= ?")
    const usernameCheck=usernameStatement.get(req.body.username)  
    
    if (usernameCheck) errors.push("Username already taken")
    if (!req.body.password) errors.push("Please provide a password.")
    if (req.body.password && req.body.password.length < 8) errors.push("password must be atleast 8 characters long")
    if (req.body.password && req.body.password.length > 70) errors.push("password must be atmost 70 characters long")
    
    if (errors.length){
        return res.render("homepage", {errors})
    }

    // save the new user into a database
    const salt =bcrypt.genSaltSync(10)
    req.body.password=bcrypt.hashSync(req.body.password, salt)

    const ourStatement = db.prepare("INSERT INTO users (username, password) VALUES (?, ?)")
    const result = ourStatement.run(req.body.username, req.body.password)

    const lookupStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ourUser = lookupStatement.get(result.lastInsertRowid)

    // log the user in by giving them a cookie
    const ourToken=jwt.sign({exp: Math.floor(Date.now()/ 1000) + 60 * 60 * 24, skyColor: "blue", userid: ourUser.id, username: ourUser.username}, process.env.JWTSECRET)

    res.cookie("ourSimpleApp",ourToken, {
        httpOnly: true,
        secure: false,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
    res.redirect("/")
})

app.listen(3000)