import express from 'express'
import bodyParser from 'body-parser'
import cors from 'cors'
import mongoose from 'mongoose'
import crypto from 'crypto'
import bcrypt from 'bcrypt-nodejs'

const mongoUrl =  "mongodb://localhost/authAPI"
mongoose.connect(mongoUrl, { useNewUrlParser: true, useUnifiedTopology: true })
mongoose.Promise = Promise

// Defines the port the app will run on. Defaults to 8080, but can be 
// overridden when starting the server. For example:
//

const User = mongoose.model('User', {
  username: {
    type: String,
    unique: true
  },
  password: {
    type: String,
    required: true
  },
  accessToken: {
    type: String,
    default: () => crypto.randomBytes(128).toString('hex'),
    unique: true
  }
})


const authenticateUser = async (req, res, next) => {
  try {
    const user = await User.findOne({
      accessToken: req.header('Authorization'),
    });

    if (user) {
      req.user = user;
      next();
    } else {
      res
        .status(401)
        .json({ loggedOut: true, message: 'Please try logging in again' });
    }
  } catch (err) {
    res
      .status(403)
      .json({ message: 'Access token is missing or wrong', errors: err });
  }
}

//   PORT=9000 npm start
const port = process.env.PORT || 8081
const app = express()

// Add middlewares to enable cors and json body parsing
app.use(cors())
app.use(bodyParser.json())

// Start defining your routes here
app.get('/', (req, res) => {
  res.send('Hello world')
})

// Create user - sign up
app.post('/users', async (req, res) => {
  try {
    const { username, password } = req.body
    // DO NOT STORE PLAINTEXT PASSWORDS
    const salt = bcrypt.genSaltSync(10)
    console.log(username, password)
    const user = await new User({ 
      username, 
      password: bcrypt.hashSync(password, salt) 
    })
    user.save()
    console.log(username, password)
    res.status(201).json({ userId: user._id, accessToken: user.accessToken})
  } catch (err) {
    res.status(400).json({ message: 'Could not create user', errors: err.errors })
  }
})

// secure endpoint, user needs to be logged in to access this
app.get('/secrets', authenticateUser)
app.get('/secrets', (req, res) => {
  res.json({ secret: 'This is a super secret message.' })
})

// Login user
app.post('/sessions', async (req, res) => {
  try {
    const { username, password } = req.body;
    const user = await User.findOne({ username })
    if (user && bcrypt.compareSync(password, user.password)) {
      res.json({ userId: user._id, accessToken: user.accessToken })
    } else {
      throw 'User not found'
    }
  } catch (err) {
    res.status(404).json({ error: 'User not found' })
  }

})

// Start the server
app.listen(port, () => {
  console.log(`Server running on http://localhost:${port}`)
})
