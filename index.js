const express = require('express')
const Datastore = require('nedb-promises')
const bcrypt = require('bcryptjs')
const jwt = require('jsonwebtoken')
const {authenticator} = require('otplib')
const qrcode = require('qrcode')
const config = require('./config')
const app = express()
app.use(express.json())
const users = Datastore.create("Users.db")
const refreshTokens = Datastore.create("Tokens.db")
const invalidTokens = Datastore.create("InvalidTokens.db")

app.get('/',(req,res)=>{

    res.send("AUTHENTICATION AND AUTHORIZATION")
})


app.post('/api/auth/register', async (req,res)=>{
    try{
        const {name , email , password,role} = req.body
        if(!name || !email || !password){
            return res.status(422).json({message:"Please fill all the fields"})
        }

        if(await users.findOne({email})){
            return res.status(409).json({message:"Email already exists"})
        }
        const hashedPassword = await bcrypt.hash(password,10)
        const newUser = await users.insert(
            {
                name, 
                email,
                password:hashedPassword,
                role:role ?? 'member',
                '2faEnable':false,
                '2faSecret':null
            }
        )
        return res.status(201).json({message:"User Registered successfully",id:newUser._id})
        
    }catch(error){
        return res.status(500).json({message:error.message})
    }

})

app.post('/api/auth/login', async (req,res)=>{
    try{
        const {email , password} = req.body
        if(!email || !password){
            return res.status(422).json({message:"Please fill all the fields"})
        }
        const user = await users.findOne({email})
        if(!user){
            return res.status(401).json({message:"Invalid email or password"})
        }
        const check = await bcrypt.compare(password,user.password)

        if(!check){
            return res.status(401).json({message:"Invalid email or password"})
        }

        const accessToken =  jwt.sign({userId:user._id},config.accessTokenSecret,{subject:"accessApi" , expiresIn:config.accessTokenExpiresIn})


        const refreshToken = jwt.sign({userId:user._id} , config.refreshTokenSecret ,{subject:"refreshApi" , expiresIn:config.refreshTokenExpiresIn})
        await refreshTokens.insert({
            refreshToken,
            userId:user._id
        })
        return res.status(200).json({
            id:user._id,
            name:user.name,
            email:user.email,
            accessToken,
            refreshToken
            
        })

    }catch(error){
        return res.status(500).json({message:error.message})
    }
})

app.post('/api/auth/refreshvalidate', async (req,res)=>{
    const refreshToken = req.headers.authorization

    if(!refreshToken) {
        return res.status(401).json({message:"No Refresh Token Found"})
    }

    try{
        const decodedValue = jwt.verify(refreshToken,config.refreshTokenSecret)
        const token = await refreshTokens.findOne({userId:decodedValue.userId, refreshToken})

        if(!token){
            return res.status(404).json({message:"Refresh Token expired or invalid"})
        }
        const user = await users.findOne({_id:decodedValue.userId})
    
        const accessToken = jwt.sign({userId:user._id},config.accessTokenSecret,{subject:"accessApi" , expiresIn:config.accessTokenExpiresIn})
    
    await refreshTokens.removeMany({_id:decodedValue.userId , refreshToken})

    const newRefreshToken = jwt.sign({userId:decodedValue.userId},config.refreshTokenSecret,{subject:"refreshApi" , expiresIn:config.refreshTokenExpiresIn})
    await refreshTokens.insert({
        refreshToken: newRefreshToken,
        userId:decodedValue.userId
    })

    return res.status(200).json({
        accessToken,
        refreshToken: newRefreshToken
    })
    }catch(error)
    {
        if(error instanceof jwt.TokenExpiredError || error instanceof jwt.JsonWebTokenError){
            return res.status(401).json({message:"Refresh Token expired or invalid"})
        }
        

        return res.status(500).json({message:error.message})
    }
    

    


})

app.get('/api/auth/2fa/generate' , ensureAuthentication ,async (req,res)=>{
    try{
        const user = await users.findOne({_id:req.user.id})
        const secret = authenticator.generateSecret()
        const uri = authenticator.keyuri(user.email,'abhi',secret)

        await users.update({_id:user._id},{$set:{'2faSecret':secret}})
        await users.compactDatafile()
        const qrCode = await qrcode.toBuffer(uri , {type:'image/png', margin:1})

        res.setHeader('Content-Disposition','attachment; filename=qrcode.png')

        return res.status(200).type('image/png').send(qrCode)
    }catch(error){
        return res.status(500).json({message:error.message})
    }
})

app.post('/api/auth/2fa/validate',ensureAuthentication,async (req,res)=>{
    try{
        const {totp} = req.body
        if(!totp){
            return res.status(422).json({message:"TOTP required"})
        }

        const user = await users.findOne({_id:req.user.id})
        const verified = authenticator.check(totp , user['2faSecret'])


        if(!verified){
            return res.status(400).json({message:"invalid or expired totp"})
        }

        await users.update({_id:req.user.id},{$set:{ '2faEnale':true}})
        await users.compactDatafile()

        return res.status(200).json({message:"Validated OTP"})
    }catch(error){
        return res.status(500).json({message:error.message})
    }
})

app.get('/api/auth/logout',ensureAuthentication, async(req,res)=>{
    
    try{
        await refreshTokens.removeMany({userId:req.user.id})
        await invalidTokens.insert({
        accessToken: req.accessToken.value,
        userId : req.user.id,
        expirationTime : req.accessToken.exp

    })
    return res.status(200).json({message:"logout"})
    }catch(error){
        return res.json({message:error.message})
    }


})

app.get('/api/auth/current' ,ensureAuthentication,async (req,res)=>{
    try{
        const user = await users.findOne({_id:req.user.id})
        return res.status(200).json({
            id: user._id,
            name:user.name,
            email:user.email
        })


    }catch(error){
        return res.status(500).json({message:error.message})
    }
} )

app.get('/api/auth/admin' , ensureAuthentication ,authorize(['admin']), (req,res)=>{
    return res.status(200).json({message:"You are admin so you are allowed to access this endpoint"})
})

app.get('/api/auth/moderator' , ensureAuthentication ,authorize(['admin','moderator']), (req,res)=>{
    return res.status(200).json({message:"Only admin and moderators can access this route"})
})

function authorize(roles=[]) {
    return async function (req,res,next) {
        const user = await users.findOne({_id:req.user.id })

        if(!user || !roles.includes(user.role)){
            return res.status(403).json({message:"Not Authorized"})
        }
        next()
    }
}

async function ensureAuthentication( req , res , next){
    const accessToken = req.headers.authorization
    if(!accessToken){
        return res.status(401).json({message:"Access token not found"})
    }
    if(await invalidTokens.findOne({accessToken})){
        return res.status(401).json({message:"Token Invalid"})
    }
    try{
        const decodedAccessToken = jwt.verify(accessToken,config.accessTokenSecret)
        
        req.accessToken = {value:accessToken,exp:decodedAccessToken.exp}
        req.user = {id:decodedAccessToken.userId}
        next()
    }
    catch(error){

        if(error instanceof jwt.TokenExpiredError){
            return res.status(401).json({message:"Token Expired",code:"AccessTokenExpired"})
        }else if(error instanceof jwt.JsonWebTokenError){
            return res.status(401).json({message:"Invalid Token",code:"InvalidAccessToken"})
        }else{
            return res.status(500).json({message:error.message})
        }
        
    }
}



app.listen(3000,()=>{
    console.log("Server has started")
})