const express = require ('express')
const crypto = require ('crypto')
const jwt = require ('jsonwebtoken')
const Users  = require ('../models/users')
const {isAuthenticated} = require('../auth')
const cors = require ('cors')

const router = express.Router()

const singToken = (id) =>{
    return jwt.sign({_id}, 'mi-secreto',{
        expiresIn: 60 * 60 * 24 * 365,
    })
}
router.post('/register', (req, res) =>{
    const {email, password} = req.body
    crypto.randomBytes(16, (err, salt) =>{
        const newSalt = salt.toString('base64')
        crypto.pbkdf2(password, newSalt, 10000, 64, 'sha1', (err, key) =>{
            const encryptedPassword = key.toString('base64')
            Users.findOne({email}).exec()
            .then(user =>{
                if (user){
                    return res.send('usuario ya existe')
                }
                Users.create({
                    email,
                    password: encryptedPassword,
                    salt: newSalt,
                }).then(() =>{
                    res.send('usuario creado con exito')
                })
            })
        })
    })
})

router.post('/login', (req, res) =>{
    const { email, password} = req.body
    Users.findOne({email}).exec()
    .then(user =>{
        if(!user) {
            return res.send('usuario y/o contraseña incorrecta')
        }
        crypto.pbkdf2(password, user.salt, 10000, 64, 'sha1', (err, key) =>{
            const encryptedPassword = key.toString('base64')
            if (user.password === encryptedPassword){
                const token = singnToken(user._id)
                return res.send({token})
            }
            res.send ('usuario y/o contraseña incorrecta')
        })
    })
})

router.get('/me', isAuthenticated, (req, res)=> {
    res.send(req.user)
})

module.exports = router