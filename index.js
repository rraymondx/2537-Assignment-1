/* REQUIRED */
require("./utils.js");
require('dotenv').config();
const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const Joi = require("joi");
const saltRounds = 12;

const port = process.env.PORT || 3000;

const app = express();

const expireTime = 60 * 60 * 1000 // 1 hour in milliseconds

/* secret section */
const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;
/* end point */

const { database } = include('databaseConnection');
const userCollection = database.db(mongodb_database).collection('users');
app.use(express.urlencoded({extended: false}));

var mongoStore = MongoStore.create({
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/`,
    crypto: {
        secret:mongodb_session_secret
    }
});

app.use(session({
    secret: node_session_secret,
    store: mongoStore,
    saveUninitialized: false,
    resave: true,
}));

app.get('/', (req, res) => {
    
    if (!req.session.authenticated) {
        var html = `
        <form action="/signup" method="get">
            <button type="submit">Sign Up</button>
        </form>
        <form action="/login" method="get">
            <button type="submit">Login</button>
        </form>
        `;
        return res.send(html);
    } else {
        var html = `
        <h2>Hello, ${req.session.username}!</h2>
        <form action="/members" method="get">
            <button type="submit">Go to members page</button>
        </form>
        <form action="/logout" method="get">
            <button type="submit">Logout</button>
        </form>
        `;
        return res.send(html);
    }

});

/* SIGNING UP AN USER */
app.get('/signup', (req, res) => {
    var html = `
    create user
    <form action='/signupSubmit' method='post'>
    <input name='username' type='text' placeholder='name'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    `;
    res.send(html);
});

/* Post screen for after signup */
app.post('/signupSubmit', async (req, res) => {
    const { username, email, password } = req.body;

    // Define Joi schema
    const schema = Joi.object({
        username: Joi.string().alphanum().max(20).required(),
        email: Joi.string().email().required(),
        password: Joi.string().max(20).required()
    });

    // Validate the request body against the schema
    const validationResult = schema.validate(req.body, { abortEarly: false });

    if (validationResult.error) {
        // If there are validation errors, send a response with error messages
        const errorMessage = validationResult.error.details.map(d => d.message).join(', ');
        const errorFields = validationResult.error.details.map(d => d.context.key).join(', ');

        let errorMessages = [];

        if (errorFields.includes('username')) {
            errorMessages.push('Username is required.<br>');
        }
        if (errorFields.includes('email')) {
            errorMessages.push('Email is required.<br>');
        }
        if (errorFields.includes('password')) {
            errorMessages.push('Password is required.<br>');
        }

        const responseMessage = errorMessages.join(' ');

        return res.status(400).send(`${responseMessage} <br> <a href="/signup">Try again</a>`);
    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

        await userCollection.insertOne({username: username, email: email, password: hashedPassword});
        console.log("Inserted User Correctly");

    req.session.authenticated = true;
    req.session.username = username;
    req.session.cookie.maxAge = expireTime;

    res.redirect('/members');
    return;
    
    
});
/* END OF SIGNING UP */

/* LOGGING IN AN USER */
app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/loggingin' method='post'>
    <input name='email' type='email' placeholder='email'><br>
    <input name='password' type='password' placeholder='password'><br>
    <button>Submit</button>
    `;
    res.send(html);
});

app.post('/loggingin', async (req, res) => {
    var username = req.body.username;
    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.string().email().required();
    const validationResult = schema.validate(email);
    if (validationResult.error != null) {
        console.log(validationResult.error);
        var html = `
        Invalid email/password combination.<br>
        <a href="/login">Try again</a>
        `;
        res.send(html);
        return;
    }

    const result = await userCollection.find({email: email}).project({email: 1, password: 1, _id: 1}).toArray();
    console.log(result);

    if (result.length != 1) {
        console.log("email not found");
        var html = `
        Invalid email/password combination.<br>
        <a href="/login">Try again</a>
        `;
        res.send(html);
        return;
    }

    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    } else {
        console.log("Incorrect password");
        var html = `
        Invalid email/password combination.<br>
        <a href="/login">Try again</a>
        `;
        res.send(html);
        return;
    }

});
/* END OF LOGGING IN */

app.get('/members', async (req, res) => {
    if(!req.session.authenticated) {
        console.log("invalid session");
        res.redirect('/');
        return;
    }

    const photoFiles = ['cat1.gif', 'cat2.gif', 'cat3.gif'];
    const randomIndex = Math.floor(Math.random() * photoFiles.length);
    const randomCat = photoFiles[randomIndex];

    var html = `
    <h2>Hello, ${req.session.username}<h2>
    <img src="/${randomCat}" alt="RandomCat"><br>
    <form action='/logout' method='get'>
        <button type="submit">Sign out</button>
    <form>
    `;
    res.send(html);
});

app.get('/logout', (req, res) => {
    req.session.destroy();
    console.log("session destroyed");
    res.redirect('/');
});

app.use(express.static(__dirname + "/public"));

app.get("/does_not_exist", (req, res) => {
    res.status(404)
    res.send("Page not found - 404");
});

app.get("*", (req, res) => {
    res.redirect("/does_not_exist");
});

app.listen(port, () => {
    console.log(`Example app listening at http://localhost:${port}`);
});