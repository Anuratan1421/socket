const express = require('express');
const bodyParser = require('body-parser');
const mongoose = require('mongoose');
const crypto = require('crypto');
const nodemailer = require('nodemailer');
const axios = require('axios');

const app = express();
const port = 8000;
const cors = require('cors');

const http = require('http').createServer(app);
const io = require("socket.io")(http, {
  cors: {
    origin: "*",
    methods: ["GET", "POST"],
  },
})

app.use(cors());

app.use(bodyParser.urlencoded({extended: false}));
app.use(bodyParser.json());
app.use(express.json());

const { GoogleGenerativeAI } = require('@google/generative-ai'); 

const jwt = require('jsonwebtoken');

mongoose
  .connect('mongodb+srv://anuratan:Anuratan%401421@cluster0.0uo5r.mongodb.net/?retryWrites=true&w=majority')
  .then(() => {
    console.log('Connected to MongoDB');
  })
  .catch(error => {
    console.log('Error connecting to MongoDB', error);
  });

http.listen(port, () => {
  console.log('Server is running on 3000');
});

const User = require('./models/user');
const Chat = require('./models/message');

// Sample music database
const sampleSongs = [
  { id: '1', title: 'Shape of You', artist: 'Ed Sheeran', duration: '3:53', coverUrl: 'https://example.com/shape-of-you.jpg' },
  { id: '2', title: 'Blinding Lights', artist: 'The Weeknd', duration: '3:20', coverUrl: 'https://example.com/blinding-lights.jpg' },
  { id: '3', title: 'Dance Monkey', artist: 'Tones and I', duration: '3:29', coverUrl: 'https://example.com/dance-monkey.jpg' },
  { id: '4', title: 'Uptown Funk', artist: 'Mark Ronson ft. Bruno Mars', duration: '4:30', coverUrl: 'https://example.com/uptown-funk.jpg' },
  { id: '5', title: 'Someone Like You', artist: 'Adele', duration: '4:45', coverUrl: 'https://example.com/someone-like-you.jpg' },
];

// Backend Route to Create User and Generate Token
const bcrypt = require('bcryptjs');

let embeddingPipeline; // Cache the pipeline

// Helper to generate embeddings locally
async function getEmbedding(inputText) {
  const { pipeline } = await import('@xenova/transformers');

  const extractor = await pipeline('feature-extraction', 'Xenova/all-MiniLM-L6-v2');
  const output = await extractor(inputText, { pooling: 'mean', normalize: true });

  return output.data; // array of numbers
}

app.post('/register', async (req, res) => {
  try {
    const { password, ...userData } = req.body;

    // Hash the password
    const saltRounds = 10;
    const hashedPassword = await bcrypt.hash(password, saltRounds);

    // Generate encryption key
    const encryptionKey = crypto.randomBytes(32).toString('hex');

    // Extract embedding-relevant fields
    const { location, education, prompts } = userData;
    const promptsText = prompts?.map(p => `${p.question} ${p.answer}`).join(' ') || '';
    const embeddingInput = `${location} ${education} ${promptsText}`;

    // Generate embedding locally
    const embeddingOutput = await getEmbedding(embeddingInput);
    
    // Convert Float32Array to regular array
    const embedding = Array.from(embeddingOutput);

    // Create new user
    const newUser = new User({
      ...userData,
      password: hashedPassword,
      encryptionKey,
      embedding,
    });

    await newUser.save();

    // Generate JWT token
    const token = jwt.sign({ userId: newUser._id }, encryptionKey);

    res.status(201).json({ token });
  } catch (error) {
    console.error('Error creating user:', error);
    res.status(500).json({ error: 'Internal Server Error' });
  }
});

//fetch users data
app.get('/users/:userId', async (req, res) => {
  try {
    const {userId} = req.params;

    const user = await User.findById(userId);

    if (!user) {
      return res.status(500).json({message: 'User not found'});
    }

    return res.status(200).json({user});
  } catch (error) {
    res.status(500).json({message: 'Error fetching the user details'});
  }
});

//endpoint to login
// Endpoint to login
app.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if the user exists
    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    // Compare the plain password with the hashed password stored in the database
    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ message: 'Invalid email or password' });
    }

    const secretKey = crypto.randomBytes(32).toString('hex');
    const token = jwt.sign({ userId: user._id }, secretKey);

    return res.status(200).json({ token });
  } catch (error) {
    res.status(500).json({ message: 'Login failed' });
  }
});

// Add this to your existing Express app setup
app.get('/api/songs/search', (req, res) => {
  const query = req.query.q?.toLowerCase() || '';
  const results = sampleSongs.filter(
    song => song.title.toLowerCase().includes(query) || 
            song.artist.toLowerCase().includes(query)
  );
  res.json(results);
});

app.get('/api/songs/:id', (req, res) => {
  const song = sampleSongs.find(s => s.id === req.params.id);
  if (song) {
    res.json(song);
  } else {
    res.status(404).json({ error: 'Song not found' });
  }
});

// Cosine similarity function
function cosineSimilarity(vecA, vecB) {
  const dotProduct = vecA.reduce((acc, val, i) => acc + val * vecB[i], 0);
  const magnitudeA = Math.sqrt(vecA.reduce((acc, val) => acc + val * val, 0));
  const magnitudeB = Math.sqrt(vecB.reduce((acc, val) => acc + val * val, 0));
  return dotProduct / (magnitudeA * magnitudeB);
}

// /matches endpoint
app.get('/matches', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) {
      return res.status(400).json({ message: 'User ID is required' });
    }

    const currentUser = await User.findById(userId)
      .populate('matches', '_id')
      .populate('likedProfiles', '_id');

    if (!currentUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    const userEmbedding = currentUser.embedding;
    if (!userEmbedding || !Array.isArray(userEmbedding) || userEmbedding.length === 0) {
      return res.status(400).json({ message: 'User embedding is missing or invalid' });
    }

    // Exclude current user, already matched users, and already liked profiles
    const excludeIds = [
      currentUser._id.toString(),
      ...currentUser.matches.map(u => u._id.toString()),
      ...currentUser.likedProfiles.map(u => u._id.toString()),
    ];

    // Fetch potential candidates who have embeddings and aren't in the exclusion list
    const candidates = await User.find({
      _id: { $nin: excludeIds },
      embedding: { $exists: true, $not: { $size: 0 } }
    });

    // Score candidates using cosine similarity
    const scored = candidates
      .map(candidate => {
        const similarity = cosineSimilarity(userEmbedding, candidate.embedding);
        return { user: candidate, similarity };
      })
      .filter(item => item.similarity >= 0.6) // similarity threshold
      .sort((a, b) => b.similarity - a.similarity);

    // Final result
    const matches = scored.map(item => ({
      ...item.user.toObject(),
      similarity: item.similarity,
    }));

    return res.status(200).json({ matches });

  } catch (error) {
    console.error('Error in /matches:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});




app.get('/explore', async (req, res) => {
  try {
    const { userId } = req.query;
    if (!userId) return res.status(400).json({ message: 'User ID is required' });

    const currentUser = await User.findById(userId)
      .populate('matches', '_id')
      .populate('likedProfiles', '_id');

    if (!currentUser) return res.status(404).json({ message: 'User not found' });

    const userEmbedding = currentUser.embedding;
    if (!userEmbedding || !Array.isArray(userEmbedding) || userEmbedding.length === 0) {
      return res.status(400).json({ message: 'User embedding is missing or invalid' });
    }

    // Exclude self, matched, and liked users
    const excludeIds = [
      currentUser._id.toString(),
      ...currentUser.matches.map(u => u._id.toString()),
      ...currentUser.likedProfiles.map(u => u._id.toString()),
    ];

    // Step 1: Fetch all candidates with embeddings
    const candidates = await User.find({
      _id: { $nin: excludeIds },
      embedding: { $exists: true, $not: { $size: 0 } }
    });

    // Step 2: Score with cosine similarity
    const scored = candidates
      .map(candidate => {
        const similarity = cosineSimilarity(userEmbedding, candidate.embedding);
        return { user: candidate, similarity };
      })
      .filter(item => item.similarity >= 0.6) // Adjust threshold
      .sort((a, b) => b.similarity - a.similarity);

    // Step 3: Apply gender filter (optional)
    const preferredGender = currentUser.gender === 'Men' ? 'Women' :
                            currentUser.gender === 'Women' ? 'Men' : null;

    const filtered = preferredGender
      ? scored.filter(item => item.user.gender === preferredGender)
      : scored;

    // Step 4: Return result
    const matches = filtered.map(item => ({
      ...item.user.toObject(),
      similarity: item.similarity,
    }));

    return res.status(200).json({ matches });

  } catch (error) {
    console.error('Error in /matches:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

// Endpoint for liking a profile
app.post('/like-profile', async (req, res) => {
  try {
    const {userId, likedUserId, image, comment} = req.body;

    // Update the liked user's receivedLikes array
    await User.findByIdAndUpdate(likedUserId, {
      $push: {
        receivedLikes: {
          userId: userId,
          image: image,
          comment: comment,
        },
      },
    });
    // Update the user's likedProfiles array
    await User.findByIdAndUpdate(userId, {
      $push: {
        likedProfiles: likedUserId,
      },
    });

    res.status(200).json({message: 'Profile liked successfully'});
  } catch (error) {
    console.error('Error liking profile:', error);
    res.status(500).json({message: 'Internal server error'});
  }
});

app.get('/received-likes/:userId', async (req, res) => {
  try {
    const {userId} = req.params;

    const likes = await User.findById(userId)
      .populate('receivedLikes.userId', 'firstName imageUrls prompts')
      .select('receivedLikes');

    res.status(200).json({receivedLikes: likes.receivedLikes});
  } catch (error) {
    console.error('Error fetching received likes:', error);
    res.status(500).json({message: 'Internal server error'});
  }
});

const apiKey = 'AIzaSyBhuostcIitcY_OTsHqGqmiAf7mnYqExgw';  // Set your API key here
const genAI = new GoogleGenerativeAI(apiKey)

const chatHistory = {};

app.post('/generate-response', async (req, res) => {
  const { message, userId } = req.body;

  // Validation for message and userId
  if (!message || !userId) {
    return res.status(400).json({ error: 'Message and userId are required' });
  }

  // Handling chat history
  if (!chatHistory[userId]) {
    chatHistory[userId] = [];
  }

  // Save user message and limit history
  chatHistory[userId].push({ role: 'user', content: message });
  const recentMessages = chatHistory[userId].slice(-6)
    .map((msg) => `${msg.role === 'user' ? 'User' : 'AI'}: ${msg.content}`)
    .join('\n');

  const prompt = `
You're a casually charming and warm AI friend, who adapts tone based on context — fun and flirty when the moment's right, and helpful and thoughtful when needed.Dont give long answers

Before replying, **analyze the user's actual intent**:
- Is it a question that needs an answer, idea, or plan?
- Is it just casual conversation or banter?
- Is the user asking for technical help or planning something?

Then, respond accordingly:
- If they're asking "what should we do", suggest ideas or make collaborative plans.
- If it's something serious, give thoughtful and useful answers.
- If it's playful, respond in a chill, sweet tone.
- Use Hinglish, Marathi + English, or any blend the user uses naturally no need of translation until user dont ask.
- Don't give long, formal responses or interrogate the user.
- Stay in the flow — make it feel like a real back-and-forth conversation.
- If the topic is technical like "AI project", respond with a small idea or plan (not just curiosity).
- Flirty and fun replies are okay only if tone allows.
- Be flirty **only** if the tone, context, and relationship allows it.

Also:
- Detect user's language (e.g., Hinglish, Hindi, Marathi + English mix) and reply in a way that matches it naturally.
- Detect their gender (if possible) from context and respond accordingly.

Keep your vibe warm and conversational, but always grounded in the intent of the message.
    ${recentMessages}
    AI:
  `;

  try {
    const model = genAI.getGenerativeModel({ model: 'gemini-1.5-flash' });
    const result = await model.generateContent([prompt]);
    const response = await result.response;
    const text = response.text().trim();

    // Save AI reply to history
    chatHistory[userId].push({ role: 'ai', content: text });

    res.json({ reply: text });
  } catch (error) {
    console.error('Gemini API error:', error.message);
    res.status(500).json({ error: 'Failed to generate response' });
  }
});

//endpoint to create a match betweeen two people
app.post('/create-match', async (req, res) => {
  try {
    const {currentUserId, selectedUserId} = req.body;

    //update the selected user's crushes array and the matches array
    await User.findByIdAndUpdate(selectedUserId, {
      $push: {matches: currentUserId},
      $pull: {likedProfiles: currentUserId},
    });

    //update the current user's matches array recievedlikes array
    await User.findByIdAndUpdate(currentUserId, {
      $push: {matches: selectedUserId},
    });

    // Find the user document by ID and update the receivedLikes array
    const updatedUser = await User.findByIdAndUpdate(
      currentUserId,
      {
        $pull: {receivedLikes: {userId: selectedUserId}},
      },
      {new: true},
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // If the user document was successfully updated
    res.status(200).json({message: 'ReceivedLikes updated successfully'});

  } catch (error) {
    res.status(500).json({message: 'Error creating a match', error});
  }
});

// Endpoint to get all matches of a specific user
app.get('/get-matches/:userId', async (req, res) => {
  try {
    const {userId} = req.params;

    // Find the user by ID and populate the matches field
    const user = await User.findById(userId).populate(
      'matches',
      'firstName imageUrls',
    );

    if (!user) {
      return res.status(404).json({message: 'User not found'});
    }

    // Extract matches from the user object
    const matches = user.matches;

    res.status(200).json({matches});
  } catch (error) {
    console.error('Error getting matches:', error);
    res.status(500).json({message: 'Internal server error'});
  }
});


// Store active connections
const activeConnections = new Map();

// Store active music sessions
const musicSessions = new Map();

// Music rooms storage - using Map for better key-value operations
const musicRooms = new Map();


const activeUsers = new Map();

const getRoomInfo = (roomId) => {
  const room = musicRooms.get(roomId);
  if (!room) return null;
  
  return {
    roomId: room.roomId,
    hostId: room.hostId,
    participants: [...room.participants],
    song: room.song
  };
};

io.on("connection", (socket) => {
  console.log("A user is connected:", socket.id)


  socket.on("registerUser", (userId) => {
    activeConnections.set(userId, socket.id);
    console.log(`✅ Registered user ${userId} with socket ID ${socket.id}`);
  });




  socket.on("disconnect", () => {
    console.log("🧹 Socket disconnected:", socket.id);
    for (const [userId, socketId] of activeConnections.entries()) {
      if (socketId === socket.id) {
        activeConnections.delete(userId);
        console.log(`❌ Removed disconnected user ${userId}`);
        break;
      }
    }
  });

 
  // Handle incoming chat messages
  socket.on('sendMessage', async (messageData) => {
    try {
      // Create a new message
      const newMessage = new Chat(messageData);
      await newMessage.save();
      
      // Determine room ID
      const roomId = [messageData.senderId, messageData.receiverId].sort().join('_');
      
      // Broadcast to room
      io.to(roomId).emit('receiveMessage', newMessage);
    } catch (error) {
      console.error('Error sending message:', error);
    }
  });







  socket.on("music:request", ({ receiverId, senderId, song, startTime }) => {
    const receiverSocket = activeConnections.get(receiverId);
    if (receiverSocket) {
      io.to(receiverSocket).emit("music:request", { senderId, song });
    }
  });

  socket.on("music:accept", ({ senderId, song, startTime }) => {
    const senderSocket = activeConnections.get(senderId);
    if (senderSocket) {
      io.to(senderSocket).emit("music:accept", { song, startTime });
    }
  });

  socket.on("music:play", ({ receiverId, startTime }) => {
    const receiverSocket = activeConnections.get(receiverId);
    if (receiverSocket) {
      io.to(receiverSocket).emit("music:play", { startTime });
    }
  });

  socket.on("music:pause", ({ receiverId }) => {
    const receiverSocket = activeConnections.get(receiverId);
    if (receiverSocket) {
      io.to(receiverSocket).emit("music:pause");
    }
  });
  
})




io.use((socket, next) => {
  const originalEmit = socket.emit;
  socket.emit = function(event, ...args) {
    console.log(`[SOCKET ${socket.id}] EMIT: ${event}`, args.length > 0 ? args[0] : '');
    return originalEmit.apply(this, [event, ...args]);
  };
  next();
});




// http.listen(9000, () => {
//   console.log('Socket.IO server running on port 9000');
// });

app.get('/messages', async (req, res) => {
  try {
    const { senderId, receiverId } = req.query;

    const messages = await Chat.find({
      $or: [
        { senderId: senderId, receiverId: receiverId },
        { senderId: receiverId, receiverId: senderId },
      ],
    });

    // Decrypt each message
    const decryptedMessages = await Promise.all(
      messages.map(async (message) => {
        const decrypted = await message.decryptMessage();
        return { ...message._doc, message: decrypted }; // Return the decrypted message
      })
    );

    res.status(200).json(decryptedMessages);
  } catch (error) {
    res.status(500).json({ message: 'Error in getting messages', error });
  }
});

app.post('/check-email', async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email });

  if (user) {
    return res.json({ exists: true });
  }

  res.json({ exists: false });
});

app.post('/cancel-match', async (req, res) => {
  try {
    const {currentUserId, selectedUserId} = req.body;

    //update the selected user's crushes array and the matches array
    await User.findByIdAndUpdate(selectedUserId, {
     
      $pull: {likedProfiles: currentUserId},
    });

    // Find the user document by ID and update the receivedLikes array
    const updatedUser = await User.findByIdAndUpdate(
      currentUserId,
      {
        $pull: {receivedLikes: {userId: selectedUserId}},
      },
      {new: true},
    );

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // If the user document was successfully updated
    res.status(200).json({message: 'ReceivedLikes updated successfully'});

  } catch (error) {
    res.status(500).json({message: 'Error creating a match', error});
  }
});

app.post('/add-comment', async (req, res) => {
  const { userId, likedUserId, comment } = req.body;

  if (!userId || !likedUserId || !comment) {
    return res.status(400).json({ message: 'Missing required fields' });
  }

  try {
    const newComment = new Comment({
      userId,
      likedUserId,
      comment,
    });

    await newComment.save();
    res.status(200).json({ message: 'Comment added successfully' });
  } catch (error) {
    console.error('Error adding comment:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

// GET: Fetch comments for a liked user
app.get('/comments/:likedUserId', async (req, res) => {
  const { likedUserId } = req.params;

  try {
    const comments = await Comment.find({ likedUserId }).sort({ timestamp: -1 });
    res.status(200).json({ comments });
  } catch (error) {
    console.error('Error fetching comments:', error);
    res.status(500).json({ message: 'Server error' });
  }
});

app.post('/messages', async (req, res) => {
  const { senderId, receiverId, message, imageUrl, timestamp } = req.body;
  if (!senderId || !receiverId || (!message && !imageUrl)) {
    return res.status(400).json({ error: 'Missing required fields' });
  }

  try {
    const newMessage = await Chat.create({ senderId, receiverId, message, imageUrl, timestamp });
    res.status(201).json(newMessage);
  } catch (err) {
    console.error("Error saving message:", err);
    res.status(500).json({ error: 'Failed to save message' });
  }
});


app.post('/cross-profile', async (req, res) => {
  try {
    const { userId, crossedUserId } = req.body;

    // Add the crossed user's ID to the current user's crossedProfiles array
    await User.findByIdAndUpdate(userId, {
      $push: { crossedProfiles: crossedUserId },
    });

    res.status(200).json({ message: 'Profile crossed successfully' });
  } catch (error) {
    console.error('Error crossing profile:', error);
    res.status(500).json({ message: 'Internal server error' });
  }
});

console.log("Backend updated to support music sharing feature with 6-digit room codes!");
