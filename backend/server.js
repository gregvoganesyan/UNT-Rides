const express = require("express")
const app = express()

app.set("view engine", "ejs")
app.use(express.urlencoded({extended: false}))
app.use(express.static("public"))

//middleware (gets in the middle of a request and response)
app.use(function (req, res, next) {
    res.locals.errors = []
    next()
})

app.get("/", (req, res)=> {
    res.render("homepage")
})

app.get("/login", (req, res)=> {
    res.render("login")
})

app.get("/signup", (req, res)=> {
    res.render("signup")
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
    
    //no errors, save the user into a database

    //log user in by giving a cookie
})

app.listen(3000)
