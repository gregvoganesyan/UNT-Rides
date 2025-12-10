require("dotenv").config()
const express = require("express")
const bcrypt = require("bcrypt")
const jwt = require("jsonwebtoken")
const cookieParser = require("cookie-parser")
const sanitizeHTML = require("sanitize-html")
const db = require("better-sqlite3")("UNTRIDES.db")
db.pragma("journal_mode=WAL")
const path = require("path")

//database setup
const createTables = db.transaction(()=> {
    db.prepare(
        `
        CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username STRING NOT NULL UNIQUE,
        email STRING,
        password STRING NOT NULL,
        security_answer TEXT,
        isAdmin INTEGER DEFAULT 0
        )
        `
    ).run()

    db.prepare(`
        CREATE TABLE IF NOT EXISTS posts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            createdDate TEXT,
            rideTo TEXT NOT NULL,
            rideFrom TEXT NOT NULL,
            rideDate TEXT NOT NULL,
            rideTime TEXT NOT NULL,
            fare FLOAT NOT NULL,
            authorid INTEGER,
            status TEXT NOT NULL DEFAULT 'active',
            flag_reason TEXT,
            FOREIGN KEY (authorid) REFERENCES users (id)
        )
    `).run()
})
createTables()
db.prepare("UPDATE users SET isAdmin = 1 WHERE username = 'gregory'").run()
db.prepare("UPDATE users SET isAdmin = 1 WHERE username = 'iada'").run()
db.prepare("UPDATE users SET isAdmin = 1 WHERE username = 'leslie'").run()
db.prepare("UPDATE users SET isAdmin = 1 WHERE username = 'sublime'").run()
const app = express()

app.set("views", path.join(__dirname, "views"))
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

//middleware to set current page for header
app.use((req, res, next) => {
    res.locals.currentPage = req.path;
    next();
});

app.get("/", (req, res)=> {
    if (req.user) {
        const statement = db.prepare(`
            SELECT posts.*, users.username 
            FROM posts
            JOIN users ON posts.authorid = users.id
            ORDER BY datetime(posts.createdDate) DESC
        `)
        const posts = statement.all()
        return res.render("find-ride", {posts})
    }
    res.render("homepage")
})

app.get("/dashboard", (req, res)=> {
    if (req.user) {
        const statement = db.prepare(`
            SELECT posts.* 
            FROM posts 
            WHERE posts.authorid = ?
            ORDER BY datetime(posts.createdDate) DESC
        `)
        const posts = statement.all(req.user.userid)
        
        return res.render("dashboard", { posts })
    }
    res.render("login")
})

app.get("/login", (req, res)=> {
    if (req.user) {
        const statement = db.prepare(`
            SELECT posts.*, users.username 
            FROM posts
            JOIN users ON posts.authorid = users.id
            ORDER BY datetime(posts.createdDate) DESC
        `)
        const posts = statement.all()
        return res.render("find-ride", {posts})
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

    req.body.username = req.body.username.trim()

    if(!req.body.username) errors.push("Username is required!")
    if(req.body.username && req.body.username.length < 3) errors.push("Username must be at least 3 characters")
    if(req.body.username && req.body.username.length > 15) errors.push("Username cannot exceed 15 characters")
    if(req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers")
    
    if(!req.body.email) errors.push("Email is required!")
    if(req.body.email && !req.body.email.endsWith('@my.unt.edu')) errors.push("Please use your UNT email address")

    const emailCheck = db.prepare("SELECT * FROM users WHERE email = ?").get(req.body.email);
    if (emailCheck) {
        errors.push("Email already in use!");
    }

    const usernameCheck = db.prepare("SELECT * FROM users WHERE username = ?").get(req.body.username);
    if (usernameCheck) {
        errors.push("Username already in use!");
    }
    
    if(!req.body.password) errors.push("Password is required!")
    if(req.body.password && req.body.password.length < 8) errors.push("Password must be at least 8 characters")
    if(req.body.password !== req.body.confirm_password) errors.push("Passwords do not match!")
    
    if(errors.length) {
        return res.render("signup", {errors})
    }

    const salt = bcrypt.genSaltSync(10)
    const hashedPassword = bcrypt.hashSync(req.body.password, salt)

    const tempData = jwt.sign({
        username: req.body.username,
        email: req.body.email,
        password: hashedPassword,
        exp: Math.floor(Date.now() / 1000) + 300
    }, process.env.JWTSECRET)

    res.cookie("TEMP_SIGNUP", tempData, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 5
    })

    res.redirect("/security-question")
})

app.get("/security-question", (req, res) => {
    try {
        const decoded = jwt.verify(req.cookies.TEMP_SIGNUP, process.env.JWTSECRET)
        res.render("security-question")
    } catch(err) {
        return res.redirect("/signup")
    }
})

app.post("/security-question", (req, res) => {
    const errors = []
    
    const decoded = jwt.verify(req.cookies.TEMP_SIGNUP, process.env.JWTSECRET)
        
    if(!req.body.security_answer || req.body.security_answer.trim() === "") {
        errors.push("This field cannot be empty")
        return res.render("security-question", { errors })
    }

    const salt = bcrypt.genSaltSync(10)
    const hashSecurity = bcrypt.hashSync(req.body.security_answer.trim().toLowerCase(), salt)
    const existingUser = db.prepare("SELECT * FROM users WHERE username = ?").get(decoded.username)
    if (existingUser) {
        res.clearCookie("TEMP_SIGNUP")
        errors.push("Username is already taken. Please sign up again.")
        return res.render("signup", { errors })
    }
    
    const ourStatement = db.prepare("INSERT INTO users (username, email, password, security_answer) VALUES (?, ?, ?, ?)")
    const result = ourStatement.run(
        decoded.username, 
        decoded.email, 
        decoded.password,
        hashSecurity
    )
        
    const searchStatement = db.prepare("SELECT * FROM users WHERE ROWID = ?")
    const ridesUser = searchStatement.get(result.lastInsertRowid)

    const tokenVal = jwt.sign({
        exp: Math.floor(Date.now()/ 1000) + 60 * 60 * 24,
        userid: ridesUser.id,
        isAdmin: ridesUser.isAdmin
    }, process.env.JWTSECRET)

    res.clearCookie("TEMP_SIGNUP")
    res.cookie("UNTRIDES", tokenVal, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000 * 60 * 60 * 24
    })
        
    res.redirect("/")
})

app.get("/forgot-password", (req, res) => {
    res.render("forgot-password")
})

app.post("/forgot-password", (req, res) => {
    const errors = []
    
    if(typeof req.body.username !== "string") req.body.username = ""
    if(typeof req.body.security_answer !== "string") req.body.security_answer = ""
    if(typeof req.body.password !== "string") req.body.password = ""
    if(typeof req.body.confirm_password !== "string") req.body.confirm_password = ""

    req.body.username = req.body.username.trim()
    req.body.security_answer = req.body.security_answer.trim()

    if(!req.body.username) errors.push("Username is required!")
    if(!req.body.security_answer) errors.push("Security answer is required!")
    if(!req.body.password) errors.push("Password is required!")
    if(req.body.password && req.body.password.length < 8) errors.push("Password must be at least 8 characters")
    if(req.body.password !== req.body.confirm_password) errors.push("Passwords do not match!")

    if(errors.length) {
        return res.render("forgot-password", { errors })
    }
    
    const userStatement = db.prepare("SELECT * FROM users WHERE username = ?")
    const user = userStatement.get(req.body.username.trim())
    
    if (!user) {
        errors.push("Invalid username or security answer")
        return res.render("forgot-password", { errors })
    }
    
    const match = bcrypt.compareSync(req.body.security_answer.trim().toLowerCase(), user.security_answer)
    
    if (!match) {
        errors.push("Invalid username or security answer")
        return res.render("forgot-password", { errors })
    }
    
    if(req.body.password.length < 8) {
        errors.push("Password must be at least 8 characters")
        return res.render("forgot-password", { errors })
    }
    
    if(req.body.password !== req.body.confirm_password) {
        errors.push("Passwords do not match")
        return res.render("forgot-password", { errors })
    }
    
    const salt = bcrypt.genSaltSync(10)
    const hashedPassword = bcrypt.hashSync(req.body.password, salt)
    
    const updateStatement = db.prepare("UPDATE users SET password = ? WHERE username = ?")
    updateStatement.run(hashedPassword, req.body.username.trim())
    
    res.redirect("/login")
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

    const tokenVal = jwt.sign({
        exp: Math.floor(Date.now()/ 1000) + 60 * 60 * 24,
        userid: thisUser.id,
        isAdmin: thisUser.isAdmin
    }, process.env.JWTSECRET)

    res.cookie("UNTRIDES", tokenVal, {
        httpOnly: true,
        secure: true,
        sameSite: "strict", 
        maxAge: 1000 * 60 * 60 * 24
    })

    if (thisUser.isAdmin == 1) {
        return res.redirect("/admin")
    }

    res.redirect("/")
})

function mustBeLoggedIn(req, res, next){
    if (req.user){
        return next()
    }
    return res.redirect("/")
}

function formatRideDateTime(rideDate, rideTime){  
    const dateObj = new Date(rideDate + "T" + rideTime);
    const formattedDate = `${dateObj.getMonth() + 1}/${dateObj.getDate()}/${dateObj.getFullYear()}`;
    let hours = dateObj.getHours();
    const minutes = dateObj.getMinutes().toString().padStart(2, "0");
    const ampm = hours >= 12 ? "PM" : "AM";
    hours = hours % 12 || 12;
    const formattedTime = `${hours}:${minutes} ${ampm}`;  
    return { formattedDate, formattedTime, dateObj };    
}

function sharedPostValidation(req){
    const errors=[]
    if (typeof req.body.rideTo !== "string") req.body.rideTo=""
    if (typeof req.body.rideFrom !== "string") req.body.rideFrom=""
    if (typeof req.body.rideDate !== "string") req.body.rideDate=""
    if (typeof req.body.rideTime !== "string") req.body.rideTime=""
    if (typeof req.body.fare !== "string") req.body.fare=""

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
    else if (isNaN(parseFloat(req.body.fare)) || parseFloat(req.body.fare) < 0) {
        errors.push("Fare must be a valid non-negative number.")
    }
   
    return errors
}   

app.get("/create-post", mustBeLoggedIn, (req,res)=>{
    const statement = db.prepare(`
        SELECT * FROM posts 
        WHERE authorid = ?
        ORDER BY datetime(createdDate) DESC
    `)
    const posts = statement.all(req.user.userid)
    
    res.render("create-post", { posts })
})

app.post("/create-post",mustBeLoggedIn,(req, res)=>{
    const errors = sharedPostValidation(req)
    if (errors.length){
        const statement = db.prepare(`
            SELECT * FROM posts 
            WHERE authorid = ?
            ORDER BY datetime(createdDate) DESC
        `)
        const posts = statement.all(req.user.userid)
        return res.render("create-post", {errors})
    }

    const {formattedDate, formattedTime} = formatRideDateTime(req.body.rideDate, req.body.rideTime);

    const ourStatement= db.prepare(" INSERT INTO posts (rideTo, rideFrom, rideDate, rideTime, fare, authorid, createdDate) VALUES (?, ?, ?, ?, ?, ?, ?)")
    const result=ourStatement.run(req.body.rideTo, req.body.rideFrom, formattedDate, formattedTime, parseFloat(req.body.fare), req.user.userid, new Date().toISOString())

    const getPostStatement= db.prepare("SELECT * FROM posts WHERE ROWID=?")
    const realPost=getPostStatement.get(result.lastInsertRowid)

    res.redirect("/find-ride")
})

app.get("/edit-post/:id", mustBeLoggedIn, (req, res)=>{
    const statement=db.prepare("SELECT * FROM posts WHERE id=?")
    const post=statement.get(req.params.id)

    if (!post){
        return res.redirect("/")
    }

    if (post.authorid !== req.user.userid){
        return res.redirect("/")
    }

    res.render("edit-post", {post})
})

app.post ("/edit-post/:id", mustBeLoggedIn, (req, res)=>{
    const statement=db.prepare("SELECT * FROM posts WHERE id=?")
    const post=statement.get(req.params.id)

    if (!post){
        return res.redirect("/")
    }
    
    if (post.authorid !== req.user.userid){
        return res.redirect("/")
    }

    const errors=sharedPostValidation(req)
    const {formattedDate, formattedTime} = formatRideDateTime(req.body.rideDate, req.body.rideTime);

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

    res.redirect('/create-post')
})

app.post("/delete-post/:id", mustBeLoggedIn,(req, res)=>{
    const statement=db.prepare("SELECT * FROM posts WHERE id=?")
    const post=statement.get(req.params.id)

    if (!post){
        return res.redirect("/")
    }

    if (post.authorid !== req.user.userid){
        return res.redirect("/")
    }

    const deleteStatement=db.prepare("DELETE FROM posts WHERE id=?")
    deleteStatement.run(req.params.id)

    res.redirect("/create-post")
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

app.get("/find-ride", (req, res) => {
    const statement = db.prepare(`
        SELECT posts.*, users.username, users.email 
        FROM posts
        JOIN users ON posts.authorid = users.id
        ORDER BY datetime(posts.createdDate) DESC
    `)
    const posts = statement.all()

    res.render("find-ride", { posts })
})

//mobile only details page
app.get('/ride-details/:id', (req, res) => {
    const postId = req.params.id;
    
    const statement = db.prepare(`
        SELECT posts.*, users.username 
        FROM posts
        JOIN users ON posts.authorid = users.id
        WHERE posts.id = ?
    `);
    const post = statement.get(postId);
    
    if (!post) {
        return res.status(404).send('Ride not found');
    }
    
    res.render('ride-details', { post });
});

app.get("/settings", (req, res) => {
    const statement = db.prepare(`
        SELECT * FROM users WHERE id = ?
    `);

    const userDB = statement.get(req.user.userid)

    res.render("settings", {user:userDB})
});

app.get("/edit-settings", (req, res)=>{
    const statement=db.prepare("SELECT * FROM users WHERE id=?")
    const userDB = statement.get(req.user.userid);

    res.render("edit-settings", {user:userDB})
})

app.post ("/edit-settings", (req, res)=>{
    const errors=[]
    if (!req.body.username) errors.push("Username is required!");
    if (req.body.username && req.body.username.length < 3) errors.push("Username must be at least 3 characters");
    if (req.body.username && req.body.username.length > 15) errors.push("Username cannot exceed 15 characters");
    if (req.body.username && !req.body.username.match(/^[a-zA-Z0-9]+$/)) errors.push("Username can only contain letters and numbers");    
   
    //Check if username already exists
    const usernameCheck = db.prepare("SELECT * FROM users WHERE username = ?").get(req.body.username);
    if (usernameCheck && usernameCheck.id !== req.user.userid) {
        errors.push("Username already in use!");
    }

    if (errors.length) {
        return res.render("edit-settings", { errors,userDB:req.body});
    }   
    
    const updateStatement = db.prepare("UPDATE users SET username=? WHERE id=?");
    updateStatement.run(req.body.username.trim(), req.user.userid);    
    const tokenVal = jwt.sign(
        { exp: Math.floor(Date.now()/1000) + 60*60*24, userid: req.user.userid, username: req.body.username.trim() },
        process.env.JWTSECRET
    );

    res.cookie("UNTRIDES", tokenVal, {
        httpOnly: true,
        secure: true,
        sameSite: "strict",
        maxAge: 1000*60*60*24
    });

    res.redirect("/settings");
})

function mustBeAdmin(req, res, next) {
    if (req.user && req.user.isAdmin == 1) {
        return next()
    }
    res.redirect("/")
}
app.get("/admin", mustBeAdmin, (req, res)=> {
const statement = db.prepare(`
        SELECT posts.*, users.username
        FROM posts
        JOIN users ON posts.authorid = users.id
        ORDER BY datetime(posts.createdDate) DESC
    `);
    const posts = statement.all();

    const flaggedStmt = db.prepare(`
        SELECT posts.*, users.username
        FROM posts
        JOIN users ON posts.authorid = users.id
        WHERE posts.status = 'flagged'
        ORDER BY datetime(posts.createdDate) DESC
    `);
    const flagged = flaggedStmt.all();
    
    const totalRides = posts.length;
    const flaggedCount = flagged.length;

    res.render ("admin", { 
        posts,
        flagged,
        totalRides,
        flaggedCount
    });

});

app.post("/admin/approve/:id", mustBeAdmin, (req, res) => {
    const stmt = db.prepare("UPDATE posts SET status = 'approved' WHERE id = ?");
    stmt.run(req.params.id);
    res.redirect("/admin#flagged");
});

app.post("/admin/delete/:id", mustBeAdmin, (req, res) => {
    const stmt = db.prepare("DELETE FROM posts WHERE id= ?");
    stmt.run(req.params.id);
    res.redirect("/admin#flagged");
});

app.post("/flag/:id", (req, res) => {
    if (!req.user) return res.redirect("/login")

    db.prepare(`
        UPDATE posts 
        SET status = 'flagged', flag_reason = 'Flagged by user'
        WHERE id = ?
    `).run(req.params.id)

    res.redirect("/")
})

//request to join button
app.post("/request-to-join", (req, res) => {
    if (!req.user) return res.redirect("/login")
    
    const postId = req.body.postId;
    const stmt = db.prepare(`
        SELECT users.email 
        FROM posts 
        JOIN users ON posts.authorid = users.id 
        WHERE posts.id = ?
    `);
    const post = stmt.get(postId);
    
    const driverEmail = post ? post.email : 'Email not found';

    res.render("confirmation", {
        driverEmail: driverEmail
    });
});

app.listen(3000)
