//load lib
const express = require('express')
const morgan = require('morgan')
const mysql = require('mysql2/promise')
const jwt = require('jsonwebtoken')
const cors = require('cors')

//connect to MSQL database
const pool = mysql.createPool({
    host: 'localhost',
    port: 3306,
    user: process.env.DB_USER,
    password: process.env.EB_PASSWORD,
    database: 'paf2020',
    connectionLimit: 4,
    timezone: '+08:00'
})

const TOKEN_SECRET = process.env.TOKEN_SECRET
const SQL_SELECT_USER = 'select user_id, email from user where user_id=? and password = sha1(?)'

//Passport core
const passport = require('passport')
//Passport Strategy
const LocalStrategy = require('passport-local').Strategy

const mkAuth = (passport) => {
    return (req, res, next) => {
        passport.authenticate('local',
            (err, user, info) => {
                if ((null != err) || (!user)) {
                    res.status(401)
                    res.type('application/json')
                    res.json({ error: err })
                    return
                }
                //attach user to request object
                req.user = user
                next()
            }
        )(req, res, next)
    }
}

//configure passport with a strategy
passport.use(
    new LocalStrategy(
        { usernameField: 'username', passwordField: 'password' },
        async (user, password, done) => {
            //perorm the authentication
            console.info(`LocalStrategy> username: ${user}, password: ${password}`)
            const conn = await pool.getConnection()
            try {
                const [result, _] = await conn.query(SQL_SELECT_USER, [user, password])
                console.info('>>> result: ', result)
                if (result.length > 0)
                    done(null, {
                        username: result[0].user_id,
                        avatar: `https://i.pravatar.cc/400?u=${result[0].email}`,
                        loginTime: (new Date()).toString()
                    })
                else
                    done('Incorrect login', false)
            } catch (e) {
                done(e, false)
            } finally {
                conn.release
            }
        }
    )
)

const localStrategyAuth = mkAuth(passport)

const PORT = parseInt(process.env.PORT) || 3000

const app = express()
app.use(morgan('combined'))

app.use(cors())
app.use(express.json())
app.use(express.urlencoded({ extended: true }))

//initialise passport after json and form-urlencoded
app.use(passport.initialize())

app.post('login',
    //passport middleware to perform login
    //passport.authenticate('local', { session: false }),
    //authenticate with custom error handling
    localStrategyAuth,
    (req, res) => {
        //do something
        console.info(`user: `, req.user)
        //generate JWT 
        const timestamp = (new Date()).getTime() / 1000
        const token = jwt.sign({
            sub: req.user.username,
            iss: 'myapp',
            iat: timestamp,
            //nbf timestamp +30,
            exp: timestamp + (60 * 60),
            data: {
                avatar: req.user.avatar,
                loginTime: req.user.loginTime
            }
        }, TOKEN_SECRET)

        res.status(200)
        res.type('application/json')
        res.json({ mesage: `Login at ${new Date()}`, token })
    }
)

//Look for token in HTTP header
//Authorization: Bearer <token>
app.get('/protected/secret',
    (req, res, next) => {
        //check if the request has Authorization header
        const auth = req.get('Authorization')
        if (null == auth) {
            res.status(403)
            res.json({ message: 'Missing Authorization header' })
            return
        }
        //Bearer Authorization
        // Bearer <token>
        const terms = auth.split(' ')
        if ((terms.length != 2) || (terms[0] != 'Bearer')) {
            res.status(403)
            res.json({ message: 'Incorrect Authorization' })
            return
        }

        const token = terms[1]
        try {
            //verify token
            const verified = jwt.verify(token, TOKEN_SECRET)
            console.info(`Verified token: `, verified)
            req.token = verified
            next()
        } catch (e) {
            res.status(403)
            res.json({ message: 'Incorrect token', error: e })
            return
        }
    },
    (req, res) => {
        res.status(200),
            res.json({ meaning_of_life: 42 })
    }
)


//start server
app.listen(PORT, () => {
    console.info(`Application started on port ${PORT} at ${new Date()}`)
})