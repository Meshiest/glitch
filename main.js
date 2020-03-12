const express = require('express');
const uuid = require('uuid').v5;
const _ = require('lodash');
const path = require('path');
const yaml = require('js-yaml');
const bodyParser = require('body-parser');
const crypto = require('crypto');
const app = express();
const session = require('express-session');
const passport = require('passport');
const RedditStrategy = require('passport-reddit').Strategy;
const fs = require('fs');
const MongoClient = require('mongodb').MongoClient;

const config = fs.existsSync('./config.yml')
  ? yaml.safeLoad(fs.readFileSync('./config.yml', 'utf8'))
  : yaml.safeLoad(fs.readFileSync('./config.default.yml', 'utf8'));

let ensureAuthenticated, db;
const table = {};

const LOOT_UUID = 'e1d567bd-498f-4b30-9ef5-1d94b79d5b5c';

const port = process.env.PORT || config.port || 3000;

app.use(express.static(path.join(__dirname, 'assets')));
app.use(bodyParser.json());
app.use(session({
  secret: config['session-secret'],
  resave: false,
  saveUninitialized: true,
  cookie: { secure: false },
}));

const isAdmin = name => config.administrators.includes((name || '').toLowerCase());

const START_DAY = new Date('3/3/2020 12:00 CST').getTime();
const RESET_DAY = new Date('3/3/2020 4:00 CDT').getTime();
const SECOND_WEEK = new Date('3/10/2020 12:00 CDT').getTime();
const END_DATE = new Date('3/17/2020 12:00 CDT').getTime();

// things that can be indexed
const THINGS = 'r99 alt prow r301 g7 flat hem hav spit star '+
  'long trip char sent pk eva moz mast re45 ' +
  '2020 wing evo helm body knok pack '+
  'stab bolt 1x 1-2x 2-4x 2x 3x 8x anv '+
  'hmag lmag smag ' +
  '2tap fire chok hamm ring care'.split(' ');

const ARMOR = 'stab bolt helm body knok pack'.split(' ');

// determine if we want to authenticate input users
if (config['use-auth']) {
  passport.serializeUser((user, done) => done(null, user));
  passport.deserializeUser((obj, done) => done(null, obj));

  // setup passport
  passport.use(new RedditStrategy({
      clientID: config['reddit-key'],
      clientSecret: config['reddit-secret'],
      callbackURL: `${config['auth-host']}/auth/reddit/callback`
    },
    (accessToken, refreshToken, profile, done) => {
      console.log('login', profile.name);
      table.users.findOneAndUpdate(
        {redditId: profile.id},
        {$set: {
          redditId: profile.id,
          name: profile.name,
        }, $inc: {activity: 1}},
        {upsert: true, new: true},
        (err, user) => done(err, _.get(user, 'value'))
      );
    }
  ));

  app.use(passport.initialize());
  app.use(passport.session());

  app.get('/auth/reddit', (req, res, next) => {
    req.session.state = crypto.randomBytes(32).toString('hex');
    passport.authenticate('reddit', {
      state: req.session.state,
    })(req, res, next);
  });

  app.get('/auth/reddit/callback', (req, res, next) => {
    if (req.query.state == req.session.state){
      passport.authenticate('reddit', {
        successRedirect: '/',
        failureRedirect: '/'
      })(req, res, next);
    }
    else {
      next('Invalid auth');
    }
  });

  app.get('/auth/logout', (req, res) => {
    req.logout();
    res.redirect('/');
  });

  ensureAuthenticated = (req, res, next) => {
    if (req.isAuthenticated()) { return next(); }
      res.status(401).json({
        message: 'Unauthorized'
      });
  }

  app.get('/auth/check', (req, res) => {
    const name = _.get(req, 'user.name');
    table.users.findOne({ name }, (err, doc) => {
      if (err)
        return res.status(500).json({message: 'Error finding user'});

      res.json({
        isAuth: !!req.user,
        user: name,
        admin: isAdmin(name),
        banned: doc && doc.banned,
      });
    })
  });

  app.post('/api/ban', ensureAuthenticated, (req, res) => {
    const admin = isAdmin(_.get(req.user, 'name'));

    if (!admin) {
      return res.status(401).json({message: 'Unauthorized'});
    }

    const { target } = req.body;

    table.users.findOneAndUpdate(
      {name: target},
      {$bit: {
        banned: {xor: 1},
      }},
      (err, user) => {
        if (err) {
          console.log(err);
          res.status(500).json({message: 'error'});
          return;
        }
        table.votes.deleteMany({ voter: target }, (err, doc) => {
          if (err)
            return res.status(500).json({message: 'Error deleting votes'});
          res.json({message: 'ok'});
        });
      }
    );
  });
} else {
  ensureAuthenticated = (req, res, next) => next();

  app.get('/auth/check', (req, res) => {
    res.json({isAuth: true, user: null, admin: true});
  });
}

// determine if a user is banned
const isBanned = name => new Promise(resolve =>
  table.users.findOne({ name }, (err, doc) => {
    resolve(doc && !!doc.banned);
  }));

// ban user and delete all of their data
const banUser = target => {
  try {
    table.users.findOneAndUpdate({ name: target }, {$set: { banned: true, }}, (err, user) => err && console.log(err));
    table.votes.deleteMany({ voter: target }, (err, user) => err && console.log(err));
    table.things.deleteMany({ user: target }, (err, user) => err && console.log(err));
  } catch (e) {
    console.error(e);
  }
};

// count number of entries in last hour
const numRecent = name =>
  table.things.find({
    user: {$eq: name},
    created: {$gt: Date.now()-60*60*1000}
  }).count();

// input validation
function validateLoot(data) {
  if (typeof data.id !== 'string')
    return false;

  if (typeof data.x !== 'number' || typeof data.y !== 'number')
    return false;

  /// no one is sticking stuff on the edge of the map...
  if (data.x < 0.02 || data.y < 0.02 || data.x > 0.98 || data.y > 0.98)
    return false;

  if (!THINGS.includes(data.id))
    return false;

  if (data.id === 'ring' || data.id === 'care') {
    if (typeof data.round !== 'number')
      return false;

    if (data.round < 1 || data.round > 7)
      return false;
  }

  if (ARMOR.includes(data.id) && data.color !== 'gold' && data.color !== 'purple') {
    if (data.id === 'body' && data.color !== 'blue') {
      return false;
    }
  }

  return true;
}

// automatically ban users who contribute maliciously too many times
function punish(user, session) {
  const now = Date.now();
  // reset every 2 minutes for strike counting
  if (!session.strikeStart || now - session.strikeStart > 120000) {
    session.strikeStart = now;
    session.strikes = 0;
  }

  session.strikes = session.strikes || 0;
  session.strikes++;

  // if you fail 100+ times within 2 minutes, you're probably a bot
  if (session.strikes > 100 && now - session.strikeStart < 120000)
    banUser(user.name);
}

// posting new data to the map
app.post('/api/data', ensureAuthenticated, async(req, res) => {
  const now = Date.now();
  const name = _.get(req.user, 'name');
  const admin = isAdmin(name);

  if (config['use-auth'] && config['only-admins'] && !admin) {
    return res.status(401).json({message: 'Admin only mode'});
  }

  const banned = await isBanned(name);
  if (banned) {
    return res.status(401).json({message: 'Unauthorized'});
  }

  // one item per minute for untrusted users
  const shouldCooldown = config['use-auth'] && !_.get(req.user, 'trusted') && !admin;

  if (shouldCooldown && now > END_DATE) {
    return res.status(412).json({message: 'Event Complete'});
  }

  if (shouldCooldown && await numRecent(name) > 100) {
    banUser(name);
    return res.status(401).json({message: 'Unauthorized'});
  }

  if (shouldCooldown && req.session.dataCooldown && now - req.session.dataCooldown < 10000) {
    punish(req.user, req.session);
    return res.status(429).json({message: 'Too many requests'});
  }


  if(!validateLoot(req.body)) {
    return res.status(422).json({message: 'Invalid Arguments'});
  }

  const {x, y, id, round, color} = req.body;

  const data = {
    uuid: uuid(`${id}:${x},${y}:${round||0}`, LOOT_UUID),
    user: _.get(req.user, 'name', 'guest'),
    created: now,
    thing: id,
    x: x,
    y: y,

    // round only for ring or care package
    ...(id === 'ring' || id === 'care' ? {
      round: round,
    } : {}),

    // round only for ring or care package
    ...(ARMOR.includes(id) ? {
      color: color,
    } : {}),
  }

  req.session.dataCooldown = now;

  table.things.insertOne(data, (err, doc) => {
    if (err) {
      console.error(err);
      res.status(500).json({message: 'Error inserting thing'});
      return;
    }

    res.status(shouldCooldown ? 201 : 200).json({ ...data, ago: 0, good: 0, bad: 0 });
  });
});

// voting request
app.post('/api/vote', ensureAuthenticated, async (req, res) => {
  const voter = _.get(req.user, 'name', 'guest');
  const { uuid, vote } = req.body;
  const admin = isAdmin(voter);

  const shouldCooldown = config['use-auth'] && !_.get(req.user, 'trusted') && !admin;

  const now = Date.now();
  if (shouldCooldown && req.session.voteCooldown && now - req.session.voteCooldown < 500) {
    punish(req.user, req.session);
    return res.status(429).json({message: 'Too many requests'});
  }
  req.session.voteCooldown = now;

  const banned = await isBanned(voter);
  if (banned) {
    return res.status(401).json({message: 'Unauthorized'});
  }

  if (vote !== -1 && vote !== 1 && vote !== 0)
    return res.status(422).json({message: 'Invalid Vote'});

  table.things.findOne({ uuid }, (err, doc) => {
    if (err)
      return res.status(500).json({message: 'Error finding thing'});
    if (!doc)
      return res.status(404).json({message: 'Thing is missing'});

    table.votes.findOneAndUpdate(
      {voter, uuid},
      {$set: {voter, uuid, vote}},
      {upsert: true, new: true},
      (err, doc) => {
        res.json({message: 'ok'});
      }
    );
  })
});

// delete a thing and its vote
app.post('/api/delete', ensureAuthenticated, async (req,res) => {
  const user = _.get(req.user, 'name', 'guest');
  const { uuid } = req.body;

  const admin = isAdmin(user);
  const isNotAdmin = config['use-auth'] && !admin;

  const banned = await isBanned(user);
  if (banned) {
    return res.status(401).json({message: 'Unauthorized'});
  }

  // prevent users from deleting data after the event
  const now = Date.now();
  if (isNotAdmin && now > END_DATE) {
    return res.status(412).json({message: 'Event Complete'});
  }

  table.things.findOne({ uuid }, (err, doc) => {
    if (err)
      return res.status(500).json({message: 'Error finding thing'});
    if (!doc)
      return res.status(404).json({message: 'Thing is missing'});

    if (doc.user !== user && !isAdmin(user) && doc.user !== 'guest')
      return res.status(401).json({message: 'You cannot delete this'});

    table.things.deleteOne({ uuid }, (err, doc) => {
      if (err)
        return res.status(500).json({message: 'Error deleting thing'});
      table.votes.deleteMany({ uuid }, (err, doc) => {
        if (err)
          return res.status(500).json({message: 'Error deleting votes'});
        res.json({message: 'ok'});
      });
    });
  });
});

app.get('/api/data', (req, res) => {
  const handle = (err, docs) => {
    if (err) {
      console.error(err);
      res.status(500).json({
        status: 500,
        message: 'Error requesting loot table',
      });
      return;
    }
    res.status(200).json(docs);
  };

  const kc = !!req.query.kc;

  // determine which event day we're on
  // so we can accurately determine whether or not to display the newest ring
  const now = Date.now();
  const day = 24*60*60*1000
  const currDay = Math.floor((now - RESET_DAY)/day);
  const dayStart = RESET_DAY + currDay * day;

  table.things.aggregate([
    // select values before or after start of kings canyon week
    {$match: {
      created: {
        [kc ? '$gt' : '$lt']: SECOND_WEEK,
      },
    }},
    // only show carepackages and rings from the current day
    {$match: {
      $or: [
        {thing: {$nin: ['ring', 'care']}},
        {created: {$gt: dayStart}},
      ],
    }},

    // join on votes
    {$lookup: {from: 'votes', localField: 'uuid', foreignField: 'uuid', as: 'votes'}},
    {$unwind: {path: '$votes', preserveNullAndEmptyArrays: true}},
    {$group: {
      // group by uuid
      _id: '$uuid',

      // passthrough fields
      uuid: {$first: '$uuid'},
      user: {$first: '$user'},
      thing: {$first: '$thing'},
      color: {$first: '$color'},
      round: {$first: '$round'},

      x: {$first: '$x'},
      y: {$first: '$y'},

      // calculate time since posting
      ago: {$first: {
        $subtract: [now, '$created'],
      }},

      // get user's vote
      vote: {$sum: {$cond: [{$eq: ['$votes.voter', _.get(req.user, 'name', 'guest')]}, '$votes.vote', 0]}},

      // vote counts
      good: {$sum: {$cond: [{$and: [{$ne: ['$votes.voter', '$user']}, {$eq: ['$votes.vote', 1]}]}, 1, 0]}}, // number of +1's
      bad: {$sum: {$cond: [{$and: [{$ne: ['$votes.voter', '$user']}, {$eq: ['$votes.vote', -1]}]}, 1, 0]}}, // number of -1's
    }},
    {$project: {_id: 0}}, // remove the _id field
    {$sort: {'y': 1}}, // sort from top to bottom
  ]).toArray(handle);
});

app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, '/index.html'))
});


app.use((req, res) => {
    res.status(404).send('page not found');
});

// Use connect method to connect to the server
MongoClient.connect(config['db-url'], function(err, client) {
  if (err) {
    console.error(err);
    process.exit(1);
  }
  console.log("Connected successfully to db server");

  db = client.db(config['db-name']);
  table.users = db.collection('users');
  table.things = db.collection('things');
  table.votes = db.collection('votes');
  table.reports = db.collection('reports');

  app.listen(port, () => console.log(`Started server on :${port}!`));
});
