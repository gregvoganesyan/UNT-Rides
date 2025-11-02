require("dotenv").config()
const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser")
const db = require("better-sqlite3")("UNTRIDES.db")
db.pragma("journal_mode = WAL")

//database setup
const createTables = db.transaction(()=> {
    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        email STRING NOT NULL UNIQUE,
        password STRING NOT NULL
        )
        `
    ).run()
})

createTables()

const app = express()

app.set("view engine", "ejs")
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"))
app.use(cookieParser())

//middleware (gets in the middle of a request and response)
app.use(function (req, res, next) {
    res.locals.errors = []

    //decode incoming cookie
    try {
        const decoded = jwt.verify(req.cookies.UNTRIDES, process.env.JWTSECRET)
        req.user = decoded
    } catch(err) {
        req.user = false
    }
    res.locals.user = req.user
    console.log(req.user)
    next()
})

app.get("/", (req, res)=> {
    if (req.user) {
        return res.render("findride")
    }
    res.render("homepage")
})

app.get("/dashboard", (req, res)=> {
    if (req.user) {
        return res.render("dashboard")
    }
    res.render("login")
})

app.get("/login", (req, res)=> {
    if (req.user) {
        return res.render("findride")
    }
    res.render("login")
})

app.get("/signup", (req, res)=> {
    res.render("signup")
})

app.get("/logout", (req, res)=> {
    res.clearCookie("UNTRIDES")
    res.redirect("/login")
})

app.post("/register", (req, res)=> {
    const errors = []

    if(typeof req.body.username !== "string") req.body.username = ""
    if(typeof req.body.password !== "string") req.body.password = ""

    //trim spaces
    req.body.username = req.body.username.trim()

    if(!req.body.username) errors.push("Username is required!")
    if(req.body.username && req.body.username.length < 3) errors.push("Username must be at least 3 characters")
    if(req.body.username && req.body.username.length > 15) errors.push("Username cannot exceed 15 characters")
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers")
    
    if(!req.body.email) errors.push("Email is required!")
    if(req.body.email && !req.body.email.endsWith('@my.unt.edu')) errors.push("Please use your UNT email address")

    if(!req.body.password) errors.push("Password is required!")
    if(req.body.password && req.body.password.length < 8) errors.push("Password must be at least 8 characters")
    if(req.body.password !== req.body.confirm_password) errors.push("Passwords do not match!")
    
    if(errors.length) {
        return res.render("signup", {errors})
    }

    //hash password
    const salt = bcrypt.genSaltSync(10)
    req.body.password = bcrypt.hashSync(req.body.password, salt)

    //save new user in database
    const ourStatement = db.prepare("INSERT INTO users (username, email, password) VALUES (?, ?, ?)")
    const result = ourStatement.run(req.body.username, req.body.email, req.body.password)
    
    const searchStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ridesUser = searchStatement.get(result.lastInsertRowid)

    //create a JWT (JSON Web Token)
    const tokenVal = jwt.sign({exp: Math.floor(Date.now()/ 1000) + 60 * 60 * 24, userid: ridesUser.id}, process.env.JWTSECRET)

    //log user in by giving a cookie
    res.cookie("UNTRIDES", tokenVal, {
        //client-side JS cannot access this cookie
        httpOnly: true,
        //only send cookie over HTTPS, not HTTP
        secure: true,
        sameSite: "strict",
        //cookie is good for one day
        maxAge: 1000 * 60 * 60 * 24
    })
    
    res.redirect("/")
})

app.post("/login", (req, res)=> {
     const errors = []

    if(typeof req.body.username !== "string") req.body.username = ""
    if(typeof req.body.password !== "string") req.body.password = ""

    if (req.body.username.trim() == "") errors.push("Username or Password is invalid!")
    if (req.body.password.trim() == "") errors.push("Username or Password is invalid!")
    

    if (errors.length) {
        return res.render("login", {errors})
    }

    const userStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const thisUser = userStatement.get(req.body.username)

    if (!thisUser) {
        errors.push("Username or Password is invalid!")
        return res.render("login", {errors})
    }
    
    const match = bcrypt.compareSync(req.body.password, thisUser.password)
    
    if (!match) {
        errors.push("Username or Password is invalid!")
        return res.render("login", {errors})
    }

    //create a JWT (JSON Web Token)
    const tokenVal = jwt.sign({exp: Math.floor(Date.now()/ 1000) + 60 * 60 * 24, userid: thisUser.id}, process.env.JWTSECRET)

    //log user in by giving a cookie
    res.cookie("UNTRIDES", tokenVal, {
        //client-side JS cannot access this cookie
        httpOnly: true,
        //only send cookie over HTTPS, not HTTP
        secure: true,
        sameSite: "strict",
        //cookie is good for one day
        maxAge: 1000 * 60 * 60 * 24
    })

    res.redirect("/")

})

app.listen(3000)
