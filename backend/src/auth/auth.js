import express from 'express'
import passport from 'passport'
import LocalStrategy from 'passport-local'
import crypto from 'crypto'
import { Mongo } from '../database/mongo.js'
import jwt from 'jsonwebtoken'
import { ObjectId } from 'mongodb'

const collectionName = 'users' // Nome da coleção no Mongo onde estão os dados dos usuários

passport.use(
    new LocalStrategy(
        { usernameField: 'email' }, // Aqui a gente diz que o "usuário" será o campo de email
        async (email, password, callback) => { // Função que será chamada quando alguém tentar logar

            const user = await Mongo.db // verificar se já não existe um usuario
                .collection(collectionName)
                .findOne({ email: email }) // encontrar um email

            if (!user) {
                return callback(null, false) // se não achar ninguem vai dar nulo e falso
            }

            const saltBuffer = user.saltBuffer

            crypto.pbkdf2(password, saltBuffer, 310000, 16, 'sha256', (err, hashedPassword) => {
                if (err) {
                    return callback(null, false)
                }

                const userPasswordBuffer = Buffer.from(user.password.buffer)

                if (!crypto.timingSafeEqual(userPasswordBuffer, hashedPassword)) { // se não for igual por isso o !
                    return callback(null, false)
                }

                const { password, salt, ...rest } = user // ...rest é tudo que resta

                return callback(null, rest)
            })
        }))

const authRouter = express.Router()

authRouter.post('/signup', async (req, res) => {
    const checkUser = await Mongo.db
        .collection(collectionName)
        .findOne({ email: req.body.email })

    if (checkUser) {
        return res.status(500).send({
            success: false,
            statusCode: 500,
            body: {
                text: 'User already exit'
            }
        })
    }

    const salt = crypto.randomBytes(16)
    crypto.pbkdf2(req.body.password, salt, 310000, 16, 'sha256', async (err, hashedPassword) => {
        if (err) {
            return res.status(500).send({
                success: false,
                statusCode: 500,
                body: {
                    text: 'Error on crypto password!',
                    err: err
                }
            })
        }

        const result = await Mongo.db
            .collection(collectionName)
            .insertOne({
                email: req.body.email,
                password: hashedPassword,
                salt
            })

        if (result.insertedId) {
            const user = await Mongo.db
                .collection(collectionName)
                .findOne({ _id: new ObjectId(result.insertedId) })

            const token = jwt.sign(user, 'secret')

            return res.send({
                success: true,
                statusCode: 200,
                body: {
                    text: 'User registered correctly!',
                    token,
                    user,
                    logged: true
                }
            })
        }
    })
})

export default authRouter