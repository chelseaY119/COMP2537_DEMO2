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

const expireTime = 60 * 60 * 1000;

const mongodb_host = process.env.MONGODB_HOST;
const mongodb_user = process.env.MONGODB_USER;
const mongodb_password = process.env.MONGODB_PASSWORD;
const mongodb_database = process.env.MONGODB_DATABASE;
const mongodb_session_secret = process.env.MONGODB_SESSION_SECRET;
const node_session_secret = process.env.NODE_SESSION_SECRET;

var { database } = include('databaseConnection');

const userCollection = database.db(mongodb_database).collection('users');
const adminCollection = database.db(mongodb_database).collection('admin');

app.set('view engine', 'ejs');

app.use(express.urlencoded({ extended: false }));

var mongoStore = MongoStore.create({
    // mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@cluster0.aidihud.mongodb.net/sessions`,
    mongoUrl: `mongodb+srv://${mongodb_user}:${mongodb_password}@${mongodb_host}/a2`,
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
        res.render('index', {
            req: req,
            pageTitle: 'Home',
            buttonText1: 'Sign up',
            buttonText2: 'Log in',
            activePage: 'home'
        });
    } else {
        res.render('index', {
            req: req,
            pageTitle: 'Hello! ',
            username: req.session.username,
            buttonText1: 'Go to members area',
            buttonText2: 'Log out',
            activePage: 'home'
        });
    }
});

//sign up page
app.get('/signup', (req, res) => {
    res.render("login", {
        // req: req,
        pageTitle: 'Sign Up',
        activePage: 'login'
    });
});

app.post('/submitSignup', async (req, res) => {
    console.log('post')
    // app.post('/submitUser', (req, res) => {
    var username = req.body.username;
    var password = req.body.password;
    var email = req.body.email;
    var usertype = 'user';

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

    await userCollection.insertOne({ username: username, password: hashedPassword, email: email, userType: usertype });
    console.log("Inserted user");

    req.session.authenticated = true;
    req.session.username = username;
    res.redirect('/members');

});

//login page
app.get('/login', (req, res) => {
    res.render("login", {
        pageTitle: 'Login',
        activePage: 'login'
    })
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

    const userresult = await userCollection.find({ email: email }).project({ email: 1, password: 1, _id: 1, username: 1 }).toArray();
    const adminresult = await adminCollection.find({ email: email }).project({ email: 1, password: 1, _id: 1, username: 1 }).toArray();

    console.log(userresult);
    console.log(adminresult);
    // console.log(result);
    if (userresult.length === 0 && adminresult.length === 0) {
        var html = `
        <div>User not found</div>
        <br>
        <a href="/login">Try Again</a>
    `;
        res.send(html);
        return;
    }

    if (userresult.length === 1) {
        user = userresult[0];
    } else {
        user = adminresult[0];
    }

    if (await bcrypt.compare(password, user.password)) {
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

//admin page
app.get('/admin', async (req, res) => {

    const admin = await adminCollection.find().toArray();
    const users = await userCollection.find().toArray();

    if (!req.session.authenticated) {
        res.render('index', {
            req: req,
            pageTitle: 'Home',
            buttonText1: 'Sign up',
            buttonText2: 'Log in',
            activePage: 'home'
        });

    }

    const username = req.session.username;
    console.log(username);

    const user = await userCollection.findOne({ username });

    if(user && user.userType === 'user')  {
        res.render("404", {
            pageTitle: '403',
            activePage: '404'
        });
    }

     else {
        res.render('admin', {
            req: req,
            // userCollection: userCollection,
            users: users,
            admins: admin,
            activePage: 'admin'
        });
    };
});

app.post('/updateUserType', async (req, res) => {
    const body = req.body;
    const username = body.username;
    const userType = body.userType;

    try {
        const userDocument = await userCollection.findOne({ username });
        if (userDocument) {
            await userCollection.updateOne(
                { username },
                { $set: { userType: userType } }
            )
        }

        else if (!userDocument) {
            await adminCollection.updateOne(
                { username },
                { $set: { userType: userType } }
            )
        };

        if (userType === 'admin') {
            const userDocument = await userCollection.findOne({ username });
            if (userDocument) {
                await adminCollection.insertOne(userDocument);
                await userCollection.deleteOne({ username });
            }
        } else if (userType === 'user') {
            const adminDocument = await adminCollection.findOne({ username });
            if (adminDocument) {
                await userCollection.insertOne(adminDocument);
                await adminCollection.deleteOne({ username });
            }
        }

        console.log('User type updated and document moved successfully.');
    } catch (error) {
        console.error('Error updating user type and moving document:', error);
        res.status(500).json({ success: false, message: 'An error occurred while updating user type and moving document.' });
    }
});

//members page
app.get('/members', (req, res) => {
    if (!req.session.authenticated) {
        res.redirect('/');
    }

    const images = [
        "/fluffy.gif",
        "/tutu1.jpg",
        "/socks.gif",
    ];

    res.render("member", {
        req:req,
        images: images,
        activePage:'members'
    });

});

app.get('/logout', (req, res) => {
    req.session.destroy();
    res.redirect('/');
});

app.get("*", (req, res) => {
    res.status(404);
    res.render("404", {
        pageTitle: '404'
    });
})

app.listen(port, () => {
    console.log("Node application listening on port " + port);
}); 