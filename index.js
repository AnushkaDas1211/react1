const connectToMongo = require("./db")
const express = require('express')
const cors=require('cors')
const User=require('./models/Note');
const {body, validationResult}=require('express-validator');
const b1=require('bcryptjs');
const jwt = require('jsonwebtoken');
//const { status } = require("init");
const jwt_str="React JS";

connectToMongo()
const app = express()
app.use(express.json())
app.use(cors())
app.set("view engine","ejs")
app.use(express.urlencoded({extended: false}))


app.post('/register',async (req,res)=>{
  const errors=validationResult(req);
  if(!errors.isEmpty()){
     return res.status(500).json({errors:errors.array()});
  }
  try {
     let user = await User.findOne({email: req.body.email});
     if (user){
        return res.status(404).json({error:"user already exist"})
     }
     const salt= await b1.genSalt(6);
     const spass= await b1.hash(req.body.password, salt);
     console.log(spass);
     user =await User.create({
        name: req.body.name,
        email: req.body.email,
        password: spass,
     });
     const data={
      user:{
        id:user.id
      }
     }
     const authtoken = jwt.sign(data, jwt_str);
     res.json(authtoken)

     //res.json(user)
  } catch (error) {
     console.error(error.massage);
     res.status(600).send("Some Error occured");
  }
  
})

app.post('/login',[body('email','Enter a valid email').isEmail(),
  body('password','password cannot be empty').exists(),
  ], async (req,res)=>{
    const errors=validationResult(req);
    if(!errors.isEmpty()){
       return res.status(500).json({errors:errors.array()});
    }
    const {email,password}=req.body;
    try {
       let user = await User.findOne({email});
       if (!user){
          return res.status(406).json({error:"user not exits"})
       }
       const passcom = await b1.compare(password, user.password);
       //console.log(b1.decodeBase64());
       console.log("Page Password = "+password)
       console.log("DB Password = "+user.password)
       if(!passcom){
        return res.status(406).json({error:"password miss match"})
       }
       const data={
        user:{
          id:user.id
        }
       }
       const authtoken = jwt.sign(data, jwt_str);
       res.json("Success")
  
    } catch (error) {
       console.error(error.massage);
       res.status(700).send("Some Error occured");
    }
    
  })
  
  app.get("/fetch-detail", async(req,res) => {
    try{
      const allUser = await User.find({});
      res.send({status:"ok", data:allUser})
    }catch(err){
      console.log(err)
    }
  })
  app.post("/deleteuser", async(req, res) => {
    const {id} = req.body;
    //console.log(userid);
    try{
      const demo= await User.deleteOne({_id: id});
      //console.log(res.json());
      res.status(200).send({x:"Delete"});
      
    }catch(err){
      console.log(err);
    }
  })
  app.post("/updateuser", async(req, res) => {
    const {id,name,email,password} = req.body;
    let update = {}
    if(name && name !=="")
      update.name = name
    if(email && email !=="")
      update.email = email
    if(password && password !==""){
      const salt= await b1.genSalt(6);
      const spass= await b1.hash(password, salt);
      update.password = spass
    }
    console.log(id);
    try{
      const demo= await User.updateOne(
        {_id: id},
        {$set:update}
      );
      console.log("success");
      res.status(200).send({x:"update"});
    }catch(err){
      console.log(err);
    }
  })

  app.post('/forgot-password', async (req,res) =>{
    const {email} = req.body;
    try{
      const oldUser = await User.findOne({email});
      if(!oldUser){
        return res.send("User Not Exists!!");
      }
      const secret = jwt_str + oldUser.password;
      const token = jwt.sign({email: oldUser.email, id: oldUser._id}, secret, {expiresIn: "5m"});
      console.log(token);
      const link = `http://localhost:3001/reset-password/${oldUser._id}/${token}`;
      console.log(link);
      res.status(200).send({x:"Update"});
    }
    catch(error){}
  })
  app.get("/reset-password/:id/:token", async(req, res) =>{
    const {id, token}=req.params;
    console.log(req.params);
    const oldUser = await User.findOne({_id: id});
    if(!oldUser){
      return res.send("User Not Exists!!");
    }
    const secret = jwt_str + oldUser.password;
    try{
      const verify = jwt.verify(token, secret);
      res.render("index",{email:verify.email, status:"not verified"});
      
    }catch(error){
      console.log(error);
        res.send("Not except");
    }
  })
  
  app.post("/reset-password/:id/:token", async(req, res) =>{
    const {id, token}=req.params;
    const {password}=req.body;
    console.log(req.params);
    const oldUser = await User.findOne({_id: id});
      if(!oldUser){
        return res.send("User Not Exists!!");
      }
      const secret = jwt_str + oldUser.password;
      try{
        const verify = jwt.verify(token, secret);
        const encryptedPass= await b1.hash(password, 10);
        await User.updateOne(
          {
            _id: id,
          },
          {
            $set: {
              password: encryptedPass,
            },
          }
        );
        //res.send({x: "updated"})
        res.render("index", { email: verify.email, status:"verified"})
      }catch(error){
        console.log(error);
        res.send("Not Verified");
      }
  })
    
app.use(express.json())


app.listen(3001,()=>{
  console.log("server is ready")
})
