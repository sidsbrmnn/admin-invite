require('express-async-errors');

const path = require('path');
const flash = require('connect-flash');
const cookieParser = require('cookie-parser');
const csurf = require('csurf');
const express = require('express');
const exphbs = require('express-handlebars');
const session = require('express-session');
const mongoose = require('mongoose');
const nodemailer = require('nodemailer');
const passport = require('passport');
const LocalStrategy = require('passport-local').Strategy;

const User = require('./models/user');
const Invite = require('./models/invite');

const app = express();
const csrfProtection = csurf({ cookie: true });
const transporter = nodemailer.createTransport({
  host: 'smtp.ethereal.email',
  port: 587,
  secure: false,
  auth: {
    user: 'alek.collins@ethereal.email',
    pass: 'BFB6eB4KjsH7xQe5we',
  },
});

function ensureAuthenticated(req, res, next) {
  if (req.isUnauthenticated()) {
    return res.redirect('/login');
  }

  next();
}

passport.use(
  new LocalStrategy(
    { usernameField: 'email' },
    async function (username, password, done) {
      try {
        const user = await User.findOne({ email: username });
        if (!user) {
          return done(null, false, { message: 'Incorrect email' });
        }

        const isValidPassword = await user.comparePassword(password);
        if (!isValidPassword) {
          return done(null, false, { message: 'Incorrect password' });
        }

        return done(null, user);
      } catch (error) {
        return done(error);
      }
    }
  )
);

passport.serializeUser((user, done) => {
  done(null, user._id);
});

passport.deserializeUser(async (id, done) => {
  try {
    const user = await User.findOne({ _id: id }).lean();
    done(null, user);
  } catch (error) {
    done(error);
  }
});

app.engine('handlebars', exphbs());
app.set('view engine', 'handlebars');
app.set('views', path.join(__dirname, 'views'));

app.use(express.urlencoded({ extended: false }));
app.use(
  session({
    resave: false,
    saveUninitialized: true,
    secret: 'blehh',
  })
);
app.use(cookieParser());
app.use(flash());
app.use(passport.initialize());
app.use(passport.session());
app.use(function (req, res, next) {
  res.locals.path = req.path;
  res.locals.user = req.user;
  next();
});

app.get('/', (req, res) => {
  res.render('index');
});

app.get('/invite', csrfProtection, ensureAuthenticated, (req, res) => {
  res.render('invite', {
    csrfToken: req.csrfToken(),
    error: req.flash('error'),
    success: req.flash('success'),
  });
});

app.post('/invite', csrfProtection, ensureAuthenticated, async (req, res) => {
  const user = await User.findOne({ email: req.body.email });
  if (user) {
    req.flash('error', 'User already exists.');
    return res.redirect('/invite');
  }

  let invite = await Invite.findOne({ email: req.body.email });
  if (invite) {
    req.flash('error', 'Invite already sent.');
    return res.redirect('/invite');
  }

  invite = new Invite({ email: req.body.email });
  await invite.save();

  await transporter.sendMail({
    from: `"Fred Foo 👻" <foo@example.com>`,
    to: invite.email,
    subject: 'Invite to use app',
    text: `Confirm your invite using the link http://localhost:3000/invite/verify/${invite.token}`,
    html: `<p>Confirm your invite using the link
  <a href="http://localhost:3000/invite/verify/${invite.token}" target="_blank">
    http://localhost:3000/invite/verify/${invite.token}
  </a>
</p>`,
  });

  req.flash('success', 'Invite sent.');
  res.redirect('/invite');
});

app.get('/invite/verify/:token', csrfProtection, async (req, res) => {
  const invite = await Invite.findOne({ token: req.params.token });
  if (!invite) {
    return res.redirect('/');
  }
  if (invite.isExpired()) {
    return res.redirect('/');
  }

  res.render('invite-verify', {
    csrfToken: req.csrfToken(),
    inviteToken: invite.token,
    email: invite.email,
  });
});

app.post('/invite/verify/:token', csrfProtection, async (req, res) => {
  const invite = await Invite.findOne({ token: req.params.token });
  if (!invite) {
    return res.redirect('/');
  }
  if (invite.isExpired()) {
    return res.redirect('/');
  }

  const user = new User({
    name: req.body.name,
    email: invite.email,
    password: req.body.password,
  });
  invite.user = user._id;

  await Promise.all([user.save(), invite.save()]);

  req.login(user, (err) => {
    if (err) {
      req.flash('error', err.message);
      return res.redirect('/login');
    }

    res.redirect('/');
  });
});

app.get('/login', csrfProtection, (req, res) => {
  if (req.user) {
    return res.redirect('/');
  }

  res.render('login', {
    csrfToken: req.csrfToken(),
    message: req.flash('error'),
  });
});

app.get('/logout', (req, res) => {
  req.logout();
  res.redirect('/');
});

app.get('/register', csrfProtection, async (req, res) => {
  const usersCount = await User.countDocuments();
  if (usersCount) {
    return res.redirect('/');
  }

  res.render('register', {
    csrfToken: req.csrfToken(),
  });
});

app.post('/users', csrfProtection, async (req, res) => {
  const usersCount = await User.countDocuments();
  if (usersCount) {
    return res.redirect('/');
  }

  let user = await User.findOne({ email: req.body.email });
  if (user) {
    return res.redirect('/login');
  }

  user = new User({
    name: req.body.name,
    email: req.body.email,
    password: req.body.password,
    role: 'admin',
  });
  await user.save();

  req.login(user, (err) => {
    if (err) {
      req.flash('error', err.message);
      return res.redirect('/register');
    }

    res.redirect('/');
  });
});

app.post(
  '/users/authorize',
  csrfProtection,
  passport.authenticate('local', {
    failureFlash: true,
    failureRedirect: '/login',
    successRedirect: '/',
  })
);

app.use(function (err, req, res, next) {
  if (!req.xhr) {
    next(err);
  }

  res.status(500).send({ message: err.message });
  next();
});

(async () => {
  const MONGO_URI = process.env.MONGO_URI || 'mongodb://localhost/admin-invite';
  await mongoose.connect(MONGO_URI, {
    useNewUrlParser: true,
    useUnifiedTopology: true,
  });
  console.log('Connected to MongoDB');

  const PORT = process.env.PORT ? parseInt(process.env.PORT, 10) : 3000;
  app.listen(PORT, () => {
    console.log(`Listening on port :${PORT}`);
  });
})();
