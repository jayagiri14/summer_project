require('dotenv').config();

const express = require('express');
const authRoute = require('./routes/auth');
const cookieParser = require('cookie-parser');
const session = require('express-session');
require('./database');
const passport = require('passport');
const GoogleStrategy = require('passport-google-oauth20').Strategy;
const User = require('./database/schemas/User');

const app = express();

const server = require('http').createServer(app);
const io = require('socket.io')(server);
const { v4: uuidV4 } = require('uuid');

const { ExpressPeerServer } = require('peer');
const peerServer = ExpressPeerServer(server, {
    debug: true
});

const roomSet = new Map();
const boardroomSet = new Map();

app.use('/peerjs', peerServer);
app.use(express.json());
app.use(express.urlencoded({ extended: false }));
app.use(cookieParser());
app.use(express.static('public'));
app.set('view-engine', 'ejs');

// Session middleware
app.use(session({
    secret: process.env.SESSION_SECRET,
    resave: false,
    saveUninitialized: false
}));

// Passport config
passport.use(new GoogleStrategy({
    clientID: process.env.GOOGLE_CLIENT_ID,
    clientSecret: process.env.GOOGLE_CLIENT_SECRET,
    callbackURL: process.env.GOOGLE_CALLBACK_URL
}, async (accessToken, refreshToken, profile, done) => {
    try {
        let user = await User.findOne({ email: profile.emails[0].value });
        if (!user) {
            user = await User.create({
                email: profile.emails[0].value,
                name: profile.displayName,
                verified: true
            });
        }
        return done(null, user);
    } catch (err) {
        return done(err, null);
    }
}));

passport.serializeUser((user, done) => {
    done(null, user.id);
});

passport.deserializeUser(async (id, done) => {
    try {
        const user = await User.findById(id);
        done(null, user);
    } catch (err) {
        done(err, null);
    }
});

app.use(passport.initialize());
app.use(passport.session());

const PORT = process.env.PORT || 3000;

// Mount auth routes (these must be public)
app.use(authRoute);
app.get('/login', (req, res) => {
    res.render('login.ejs');
});
app.get('/register', (req, res) => {
    res.render('register.ejs');
});
const Code = require('./database/schemas/Code'); // Add this at the top with other requires
const { log } = require('console');

// GET /verify - only for normal users
app.get('/verify', (req, res) => {
    const user = req.session.user || req.user;
    if (!user) return res.redirect('/login');
    if (user.verified) return res.redirect('/');
    // If OAuth user (no password), skip verify
    if (!user.password){
        log('tes');
        return res.redirect('/');
    } 
    res.render('verify.ejs');
});

// POST /verify - only for normal users
app.post('/verify', async (req, res) => {
    const user = req.session.user || req.user;
    if (!user) return res.redirect('/login');
    if (user.verified) return res.redirect('/');
    if (!user.password) return res.redirect('/');
    console.log(code);
    const codeDoc = await Code.findOne({ email: user.email, code });
    if (!codeDoc) {
        return res.render('verify.ejs', { error: 'Invalid or expired code.' });
    }
    await User.updateOne({ email: user.email }, { verified: true });
    await Code.deleteOne({ _id: codeDoc._id });
    // Update session if using req.session.user
    if (req.session.user) req.session.user.verified = true;
    res.redirect('/');
});
// Auth middleware for protected routes only
function ensureAuthenticated(req, res, next) {
    const user = req.session.user || req.user;
    if (user && user.verified) return next();
    if (!user) return res.redirect('/login');
    // Only normal users (with password) should be sent to verify
    if (user.password) return res.redirect('/verify');
    // OAuth users (no password) are always considered verified
    return res.redirect('/');
}

// Protected routes
app.get('/', ensureAuthenticated, (req, res) => {
    const user = req.session.user || req.user;
    res.render("index.ejs", { name: user.name });
});

app.get('/call', ensureAuthenticated, (req, res) => {
    const user = req.session.user || req.user;
    const roomId = uuidV4();
    roomSet.set(roomId, [0, null]);
    res.redirect(`/call/${roomId}`);
});

app.get('/whiteboard', ensureAuthenticated, (req, res) => {
    const user = req.session.user || req.user;
    const boardId = uuidV4();
    boardroomSet.set(boardId, [0, user.email, null]);
    res.redirect(`/whiteboard/${boardId}`);
});

app.post('/joincall', ensureAuthenticated, (req, res) => {
    res.redirect(`/call/${req.body.code}`);
});

app.post('/joinboard', ensureAuthenticated, (req, res) => {
    res.redirect(`/whiteboard/${req.body.code}`);
});

app.get('/call/:room', ensureAuthenticated, (req, res) => {
    const user = req.session.user || req.user;
    const roomId = req.params.room;
    if (roomSet.has(roomId)) {
        res.render('room.ejs', { roomId, name: user.name });
    } else {
        res.status(404).render('notfound.ejs', { msg: "Room invalid / expired!" });
    }
});

app.get('/whiteboard/:room', ensureAuthenticated, (req, res) => {
    const user = req.session.user || req.user;
    const roomId = req.params.room;
    if (boardroomSet.has(roomId)) {
        if (boardroomSet.get(roomId)[1] == user.email)
            return res.render("whiteboard-admin.ejs", { roomId, name: user.name });
        res.render("whiteboard.ejs", { roomId, name: user.name });
    } else {
        res.status(404).render('notfound.ejs', { msg: "Board invalid / expired!" });
    }
});


app.get('*', (req, res) => {
    return res.status(404).render('notfound.ejs', { msg: null });
});

// Socket.io logic
io.on('connect', socket => {
    // Video call
    socket.on('join-room', (roomId, userId, userName) => {
        socket.join(roomId);
        const id = roomSet.get(roomId)[1];
        if (id) clearTimeout(id);
        roomSet.set(roomId, [roomSet.get(roomId)[0] + 1, null]);
        socket.broadcast.to(roomId).emit('user-connected', userId, userName, socket.id);
        socket.on('message', (username, message) => {
            socket.to(roomId).emit('message', username, message);
        });
        socket.on('disconnect', () => {
            socket.broadcast.to(roomId).emit('user-disconnected', userId);
            roomSet.set(roomId, [roomSet.get(roomId)[0] - 1, null]);
            if (roomSet.get(roomId)[0] <= 0) {
                const id = setTimeout(() => { roomSet.delete(roomId); }, 3600000);
                roomSet.set(roomId, [0, id]);
            }
        });
    });
    socket.on('username-sent', (socketId, userId, userName) => {
        socket.broadcast.to(socketId).emit('username-received', userId, userName);
    });

    // Whiteboard
    socket.on('join-board', (roomId, name) => {
        socket.join(roomId);
        const id = boardroomSet.get(roomId)[2];
        if (id) clearTimeout(id);
        boardroomSet.set(roomId, [boardroomSet.get(roomId)[0] + 1, boardroomSet.get(roomId)[1], null]);
        socket.broadcast.to(roomId).emit("notify", name);
        socket.on("draw", (data) => {
            boardroomSet.set(roomId, [boardroomSet.get(roomId)[0], boardroomSet.get(roomId)[1]]);
            socket.broadcast.to(roomId).emit('ondraw', {
                startX: data.startX,
                startY: data.startY,
                x: data.x,
                y: data.y,
                width: data.width,
                color: data.color
            });
        });
        socket.on("clearscreen", () => {
            socket.broadcast.to(roomId).emit('clear');
        });
        socket.on('disconnect', () => {
            boardroomSet.set(roomId, [boardroomSet.get(roomId)[0] - 1, boardroomSet.get(roomId)[1], null]);
            if (boardroomSet.get(roomId)[0] <= 0) {
                const id = setTimeout(() => { boardroomSet.delete(roomId); }, 3600000);
                boardroomSet.set(roomId, [0, boardroomSet.get(roomId)[1], id]);
            }
        });
    });
});

server.listen(PORT, () => {
    console.log(`Listening on PORT ${PORT}`);
});