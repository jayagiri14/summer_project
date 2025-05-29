const { Router } = require('express');
const passport = require('passport');
const User = require('../database/schemas/User');
const Code = require('../database/schemas/Code');
const { HashPassword, ComparePassword, GenerateCode } = require('../utils/helpers');
const { mailCode } = require('../utils/mail');

const router = Router();

// ========== Local Auth Routes ==========

// Render login/register
router.get('/login', (req, res) => {
    req.session.user = null;
    res.render('login.ejs', { msg: null });
});

router.post('/register', async (req, res) => {
    const { email, name, password } = req.body;
    if (email && password) {
        const userDB = await User.findOne({ email });
        if (userDB) return res.status(400).render("register.ejs", { msg: "User already exists" });

        const code = GenerateCode();
        const hashedPasswd = await HashPassword(password);

        // Create user and code first
        const newUser = await User.create({
            email,
            name,
            password: hashedPasswd,
            verified: false
        });

        await Code.create({ email, code });

        // Try to send mail
        const mailSent = await mailCode(email, code);

        req.session.user = {
            email,
            name,
            password: hashedPasswd,
            verified: false
        };

        req.session.save(() => {
            if (mailSent) {
                // Go to verify page
                return res.redirect('/verify');
            } else {
                // Show warning but still allow verification
                return res.render('verify.ejs', { msg: `Verification code could not be sent to ${email}. Please check your email settings or contact support.` });
            }
        });
    } else {
        return res.status(400).render("register.ejs", { msg: "Please fill all fields." });
    }
});

// Login (normal users)
router.post('/login', async (req, res) => {
    const { email, password } = req.body;
    if (email && password) {
        const userDB = await User.findOne({ email });
        if (!userDB) {
            return res.status(401).render('login.ejs', { msg: "Invalid Username / Password" });
        }
        // If user is an OAuth user (no password set)
        if (!userDB.password) {
            return res.status(401).render('login.ejs', { msg: "This account was created using Google. Please use 'Sign in with Google'." });
        }
        const isValid = await ComparePassword(password, userDB.password);
        if (isValid) {
            req.session.user = {
                email: userDB.email,
                name: userDB.name,
                password: userDB.password,
                verified: userDB.verified
            };
            req.session.save(() => {
                return res.redirect('/');
            });
        } else {
            return res.status(401).render('login.ejs', { msg: "Invalid Username / Password" });
        }
    } else {
        res.sendStatus(400);
    }
});
// GET /verify - only for normal users
router.get('/verify', (req, res) => {
    const user = req.session.user;
    if (!user) return res.redirect('/login');
    if (user.verified) return res.redirect('/');
    // If OAuth user (no password), skip verify
    if (!user.password || user.password === null || user.password === undefined || user.password === '') return res.redirect('/');
    res.render('verify.ejs', { msg: `Verification code sent to ${user.email}.` });
});

// POST /verify - only for normal users
router.post('/verify', async (req, res) => {router.post('/register', async (req, res) => {
    const { email, name, password } = req.body;
    if (email && password) {
        const userDB = await User.findOne({ email });
        if (userDB) return res.status(400).render("register.ejs", { msg: "User already exists" });

        const code = GenerateCode();
        const hashedPasswd = await HashPassword(password);

        // Create user and code first
        const newUser = await User.create({
            email,
            name,
            password: hashedPasswd,
            verified: false
        });

        await Code.create({ email, code });

        // Try to send mail
        const mailSent = await mailCode(email, code);

        req.session.user = {
            email,
            name,
            password: hashedPasswd,
            verified: false
        };

        req.session.save(() => {
            if (mailSent) {
                // Go to verify page
                return res.redirect('/verify');
            } else {
                // Show warning but still allow verification
                return res.render('verify.ejs', { msg: `Verification code could not be sent to ${email}. Please check your email settings or contact support.` });
            }
        });
    } else {
        return res.status(400).render("register.ejs", { msg: "Please fill all fields." });
    }
});
    const user = req.session.user;
    if (!user) return res.redirect('/login');
    if (user.verified) return res.redirect('/');
    // If OAuth user (no password), skip verify
    if (!user.password || user.password === null || user.password === undefined || user.password === '') return res.redirect('/');
    const code = req.body.code;
    const userCode = await Code.findOne({ email: user.email });
    if (!userCode) {
        const newCode = GenerateCode();
        await Code.create({ email: user.email, code: newCode });
        mailCode(user.email, newCode);
        return res.render('verify.ejs', { msg: `Code expired! A new code was sent to ${user.email}.` });
    }
    if (userCode.code == code) {
        const userDB = await User.findOne({ email: user.email });
        if (!userDB) return;
        await userDB.updateOne({ verified: true });
        await Code.deleteOne({ email: userDB.email });
        userDB.verified = true;
        req.session.user = userDB;
        return res.redirect('/');
    }
    return res.status(401).render('verify.ejs', { msg: `Invalid Code!` });
});

// Delete account (normal users)
router.post('/delete', async (req, res) => {
    if (!req.session.user || !req.session.user.verified) {
        return res.status(404).redirect('/register');
    }
    await User.deleteOne({ email: req.session.user.email });
    req.session.user = null;
    return res.status(200).redirect('/register');
});

// ========== Google OAuth Routes ==========

router.get('/auth/google',
    passport.authenticate('google', { scope: ['profile', 'email'] })
);

router.get('/auth/google/callback',
    passport.authenticate('google', { failureRedirect: '/login' }),
    async (req, res) => {
        // Handle Google profile and create/fetch user in DB
        const { email, displayName } = req.user;

        let user = await User.findOne({ email });
        if (!user) {
            user = await User.create({ email, name: displayName, password: null, verified: true });
        }

        req.session.user = user;  // make consistent with local login
        res.redirect('/');
    }
);

// Logout (works for both)
router.get('/logout', (req, res) => {
    req.logout(() => {
        req.session.destroy(() => {
            res.redirect('/login');
        });
    });
});

module.exports = router;