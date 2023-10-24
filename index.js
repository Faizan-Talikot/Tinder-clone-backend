const PORT = 8000;  //my app running on 8000 port
const express = require("express");
const { MongoClient } = require("mongodb");
const { v4: uuidv4 } = require("uuid");  //to create a unique id for every user
const bcrypt = require("bcrypt");  //to bycrypt the password
const jwt = require("jsonwebtoken"); // to provide a token for user
const cors = require("cors");
const { default: mongoose } = require("mongoose");
const uri = "mongodb+srv://faizan:1234@cluster0.e4p86uw.mongodb.net/app-data";  //mongodb uri
const http = require('http');
const app = express();
app.use(cors());
app.use(express.json());
const server = http.createServer(app);
const socketIo = require('socket.io');  //to display realtime online/offline status







const io = socketIo(server, {
  cors: {
    origin: 'http://localhost:3000',
    methods: ['GET', 'POST'],
  },
});
const onlineUsers={}  //to store all my online user

//trial api
app.get("/", (req, res) => {
  res.json("hello to my app");
});

// Create a single MongoDB client instance
const client = new MongoClient(uri);

require("./imageDetails");
const Images = mongoose.model("ImageDetails");

// POST request for signup
app.post("/signup", async (req, res) => {
  const { email, password } = req.body;  //getting email and password from body

  const generatedUserId = uuidv4();  //generating userId
  const hashedPassword = await bcrypt.hash(password, 10);  //hashing the password

  try {
    await client.connect();  //connecting to database
    const database = client.db("app-data");
    const users = database.collection("users");

    const existingUser = await users.findOne({ email });

    if (existingUser) {
      return res.status(409).send("User already exists. Please Login");  //if user already exists
    }

    const sanitizedEmail = email.toLowerCase();

    const data = {
      user_id: generatedUserId,
      email: sanitizedEmail,
      hashed_password: hashedPassword,
    };
    const insertedUser = await users.insertOne(data);    //inserting the user in database
    const token = jwt.sign(insertedUser, sanitizedEmail, {    //creating a token for user
      expiresIn: 60 * 24,
    });
    res.status(201).json({ token, userId: generatedUserId });
  } catch (err) {
    console.log(err);
  } finally{
    await client.close()
  }
});




// POST request for LOGIN
app.post("/login", async (req, res) => {
  const { email, password } = req.body;  //getting email and password from body

  try {
    await client.connect();  //connecting to database
    const database = client.db("app-data");
    const users = database.collection("users");

    const user = await users.findOne({ email });  //finding user with email
    let correctPassword;
    if(user){
       correctPassword = await bcrypt.compare(password, user.hashed_password);  //if user exists then only checking if password is correct
    }

    if (user && correctPassword) {    //if both password and email is correct then login
      const token = jwt.sign(user, email, {
        expiresIn: 60 * 24,
      });
      res.status(201).json({ token, userId: user.user_id });
    } else {
      res.status(400).json("Invalid Credentials");
    }
  } catch (err) {
    console.log(err);
  }finally{
    await client.close()
  }
});




// Get individual user
app.get("/user", async (req, res) => {
  const userId = req.query.userId;

  try {
    await client.connect();  //connecting to database
    const database = client.db("app-data");
    const users = database.collection("users");

    const query = { user_id: userId };
    const user = await users.findOne(query);  //finding user with userId
    res.send(user);
  }catch(err){
    console.log(err)
  }
});

//getting all users from our database
app.get("/gendered-users", async (req, res) => {
  const gender = req.query.gender;

  try {
    await client.connect(); //connecting to database
    const database = client.db("app-data");
    const users = database.collection("users");
    const query = { gender_identity: { $eq: gender } };
    const founduser = await users.find(query).toArray();  //finding all users with matched query

    res.send(founduser);
  }catch(err){
    console.log(err)
  }
});





//taking image from user and uploading it in images folder 
const multer = require("multer");  //to upload our image 
var path = require("path");

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, "../frontend/src/images/");   //destination to store image uploaded by user
  },
  filename: function (req, file, cb) {
    const originalFilename = file.originalname.replace(/\s+/g, ''); // Remove white spaces
    cb(null, originalFilename);
  },
});
const fileFilter = (req, file, cb) => {
  var ext = path.extname(file.originalname);
  console.log(ext);
  if (ext === ".jpg" || ext===".png") {  //image should only be jpg or png
    return cb(null, true);
  } else {
    return cb(new Error('Wrong extension type'), false);
  }
};

const upload = multer({ storage: storage, fileFilter: fileFilter }).single("image");

//api to upload or image
app.post("/upload-image", async (req, res) => {
  try {
    upload(req, res, function (err) {
      if (err instanceof multer.MulterError) {
        console.error(err);
        res.status(404).json({ error: "Multer error" });
      } else if (err) {
        console.error(err);
        res.status(404).json({ error: "An error occurred" });
      } else {
        // Determine the Content-Type based on the uploaded file's extension
        const fileExtension = req.file.originalname.split('.').pop().toLowerCase();
        let contentType;

        if (fileExtension === 'png') {
          contentType = 'image/png';
        } else if (fileExtension === 'jpeg' || fileExtension === 'jpg') {
          contentType = 'image/jpeg';
        } else {
          // Handle other file types if needed
          contentType = 'application/octet-stream'; // Default to binary data
        }

        // Get the absolute path to the dynamically uploaded PNG file
        const filePath = path.join(__dirname, req.file.path); // Use req.file.path as the dynamic path

        // Set the Content-Type header
        res.setHeader('Content-Type', contentType);

        // Set the Content-Disposition header to prompt download with the original filename
        res.setHeader('Content-Disposition', `attachment; filename="${req.file.originalname}"`);

        // Send the dynamically uploaded file
        res.sendFile(filePath);

        console.log("Function completed");
      }
    });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "Internal server error" });
  }
});
















// Update a User in the Database
app.put("/user", async (req, res) => {
  const formData = req.body.formData;

  try {
    await client.connect(); //connecting to database
    const database = client.db("app-data");
    const users = database.collection("users");

    const query = { user_id: formData.user_id };
    const updateDocument = {
      $set: {
        first_name: formData.first_name,
        dob_day: formData.dob_day,
        dob_month: formData.dob_month,
        dob_year: formData.dob_year,
        show_gender: formData.show_gender,
        gender_identity: formData.gender_identity,
        gender_interest: formData.gender_interest,
        college: formData.college,
        age: formData.age,
        url: formData.url.replace(/\s+/g, ''),
        about: formData.about,
        matches: formData.matches,
      },
    };
    const insertedUser = await users.updateOne(query, updateDocument);  //updating the user in the database with updateDocument
    res.json(insertedUser);
  }catch(err){
    console.log(err)
  }
});


//api to get matched users
app.get("/users", async (req, res) => {
  const userIds = JSON.parse(req.query.userIds);

  try {
    await client.connect();
    const database = client.db("app-data");
    const users = database.collection("users");

    const pipeline = [  //this stores all the matches that match array consist
      {
        $match: {
          user_id: {
            $in: userIds,
          },
        },
      },
    ];

    const foundUsers = await users.aggregate(pipeline).toArray();  //getting all userid and converting it into array
    res.json(foundUsers);
  } catch(err){
    console.log(err)
  }
});

// Update User with a match
app.put("/addmatch", async (req, res) => {
  const { userId, matchedUserId } = req.body;

  try {
    await client.connect();  //connecting to database
    const database = client.db("app-data");
    const users = database.collection("users");

    const query = { user_id: userId };
    const updateDocument = {
      $addToSet: { matches: { user_id: matchedUserId } },
    };
    const user = await users.updateOne(query, updateDocument);  //adding the matched userid in the user match array 
    res.send(user);
  } catch(err){
    console.log(err)
  }
});





//api to check if it's a match
app.get("/ismatch", async(req,res)=>{
  const userId = req.query.userId  //user that swipe right
  const matchedUserId = req.query.swipedUserId  //swiped user
  try {
    await client.connect();  //connecting to database
    const database = client.db("app-data");
    const users = database.collection("users");

    const query = { user_id: userId };
    const query1 = {user_id: matchedUserId}
    const user1 = await users.findOne(query); //finding user that swipe right
    const user2 = await users.findOne(query1); //finding swiped user


    const find = user2.matches.some(match => match.user_id === user1.user_id);  //finding in swiped user if we exist
      res.status(200).json({ find:find.toString(), user2: user2 })
  }catch(err){
    console.log(err)
  }
})




// Get Messages by from_userId and to_userId
app.get("/messages", async (req, res) => {
  const { userId, correspondingUserId } = req.query;
  //    console.log(userId,correspondingUserId)
  try {
    await client.connect();  //connecting to database
    const database = client.db("app-data");
    const messages = database.collection("messages");

    const query = {
      from_userId: userId,
      to_userId: correspondingUserId,
    };
    const foundMessages = await messages.find(query).toArray();   //finding all the messages
    res.send(foundMessages);
  }catch(err){
    console.log(err)
  }
});

// Add a Message to our Database
app.post("/message", async (req, res) => {
  const message = req.body.message;

  try {
    await client.connect();   //connecting to database
    const database = client.db("app-data");
    const messages = database.collection("messages");

    const insertedMessage = await messages.insertOne(message);  //inserting the message in database
    res.send(insertedMessage);
  }catch(err){
    console.log(err)
  }
});




//api to uodate the user status in database
app.put("/updatestatus",async (req,res)=>{
  const {isOnline , userId} = req.body

  try{
    await client.connect();   //connecting to database
    const database = client.db("app-data");
    const users = database.collection("users");

    const query = { user_id: userId };
    const updateDocument = {
      $set: { status: isOnline },
    };
    const options = { upsert: true };
   await users.updateOne(query,updateDocument,options)
   res.status(200)
  }catch(err){
    console.log(err)
  }
})







function getUserIdFromSocket(socket) {
  const userId = socket.userId;
  if (userId && onlineUsers[userId]) {
    return userId;
  }
  // Return null or a default value if the user is not found
  return null;
}

io.on('connection',socket=>{
  socket.on('user-joined',(userId)=>{  //io event for user joined
    console.log("backend connected")
    // console.log(userId,"backend")
    socket.userId = userId
    onlineUsers[userId] = true;
    console.log(onlineUsers)
    io.emit('userStatusChanged',{userId,online:true})
  })

  socket.on('disconnect', async() => {  //io event when user user logs out
    const userId = getUserIdFromSocket(socket); // Implement this function to get the user's ID
    console.log("disconneted")
    console.log("after disconnect",onlineUsers)
    console.log("after disconnected",userId)
    if (userId) {
      delete onlineUsers[userId];
  try{
    await client.connect();
    const database = client.db("app-data");
    const users = database.collection("users");

    const query = { user_id: userId };
    const updateDocument = {
      $set: { status: false },
    };
    const options = { upsert: true };
   await users.updateOne(query,updateDocument,options)
  }catch(err){
    console.log(err)
  }
      console.log("after usestatuschanged called")
    }
  });
})
















server.listen(PORT, () => console.log("server running on PORT" + PORT));
