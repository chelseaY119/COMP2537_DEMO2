require("./utils.js");
require('dotenv').config();

const express = require('express');
const session = require('express-session');
const MongoStore = require('connect-mongo');
const bcrypt = require('bcrypt');
const saltRounds = 12;

const port = process.env.PORT || 3001;

const app = express();

const Joi = require("joi");

//Users and Passwords (in memory 'database')
const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    // mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.aidihud.mongodb.net/sessions`,
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/sessions`,
    crypto: {
        secret: mongodb_session_secret
    }
})

app.use(session({
    secret: node_session_secret,
    store: mongoStore, //default is memory store 
    saveUninitialized: false,
    resave: true
}
));

//home page 
app.get('/', (req, res) => {
    if (!req.session.authenticated) {
        res.send(`
            <h1>Home</h1>
            <form action="/signup">
                <button type="submit">Sign up</button>
            </form>
            <form action="/login">
                <button type="submit">Log in</button>
            </form>
        `);
    } else {
        var html = `
        <h1>Hello! ${req.session.username}</h1>
        <br>
        <form action="/members">
            <button type="submit">Go to members area</button>
        </form>
        <form action="/logout">
            <button type="submit">Log out</button>
        </form>
        `;
        res.send(html);
    }
});

//sign up page
app.get('/signup', (req, res) => {
    var html = `
    sign up
    <form action='/submitSignup' method='post'>
    <input name='username' type='text' placeholder='name'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitSignup', async (req, res) => {
    console.log('post')
    // app.post('/submitUser', (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;

    const schema = Joi.object(
        {
            username: Joi.string().alphanum().max(20).required().messages({
                'string.empty': 'Please provide a username.'
            }),
            password: Joi.string().max(20).required().messages({
                'string.empty': 'Please provide a password.'
            }),
            email: Joi.string().email().required().messages({
                'string.empty': 'Please provide an email address.'
            })
        });

    const { error } = schema.validate({ username, password, email });
    if (error) {

        var errorMessage = error.details[0].message;
        var html = `
                <div>${errorMessage}</div>
                <br>
                <a href="/signup">Try Again</a>
            `;
        res.send(html);
        return;

    }

    var hashedPassword = await bcrypt.hash(password, saltRounds);

    await userCollection.insertOne({ username: username, password: hashedPassword, email: email });
    console.log("Inserted user");

    // var html = "successfully created user";
    // res.send(html);
    // Create session and redirect to members page
    req.session.authenticated = true;
    req.session.username = username;
    res.redirect('/members');

});

//login page
app.get('/login', (req, res) => {
    var html = `
    log in
    <form action='/submitLogin' method='post'>
    <input name='email' type='email' placeholder='email'>
    <input name='password' type='password' placeholder='password'>
    <button>Submit</button>
    </form>
    `;
    res.send(html);
});

app.post('/submitLogin', async (req, res) => {

    var email = req.body.email;
    var password = req.body.password;

    const schema = Joi.object(
        {
            password: Joi.string().max(20).required().messages({
                'string.empty': 'Please provide a password.'
            }),
            email: Joi.string().email().required().messages({
                'string.empty': 'Please provide an email address.'
            })
        });

    const { error } = schema.validate({ email, password });
    if (error) {

        var errorMessage = error.details[0].message;
        var html = `
                <div>${errorMessage}</div>
                <br>
                <a href="/login">Try Again</a>
            `;
        res.send(html);
        return;
    }

    const result = await userCollection.find({ email: email }).project({ email: 1, password: 1, _id: 1, username: 1 }).toArray();

    console.log(result);
    if (result.length != 1) {
        var html = `
        <div>User not found</div>
        <br>
        <a href="/login">Try Again</a>
    `;
        res.send(html);
        return;
    }

    const user = result[0];
    if (await bcrypt.compare(password, result[0].password)) {
        console.log("correct password");
        req.session.authenticated = true;
        req.session.username = user.username;
        req.session.cookie.maxAge = expireTime;

        res.redirect('/members');
        return;
    }

    else {

        var html = `
            <div>Invalid user/password combination</div>
            <br>
            <a href="/login">Try Again</a>
        `;
        res.send(html);
        return;
    }
});

app.use(express.static(__dirname + "/public"));

//members page
app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }

    const images = [
        "/tutu.jpg",
        "/tutu1.jpg",
        "/tutu3.jpg",
    ];

    const index = Math.floor(Math.random() * images.length);
    const selectedImage = images[index];

    var html = `
    <h1>Hello! ${req.session.username}</h1>
    <img src="${selectedImage}" alt="Random Image" width="380" height="500">
    <form action="/logout">
    <br>
    <button type="submit">Log out</button>
    </form>
    `;
    res.send(html);

});

app.get('/logout', (req, res) => {
    // Clear the session object
    req.session.destroy();

    // Redirect the user to the login page
    res.redirect('/');
});


app.get("*", (req, res) => {
    res.status(404);
    res.send("Page not found - 404");
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 