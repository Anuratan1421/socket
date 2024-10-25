const express = require('express');
const http = require('http');
const socketIO = require('socket.io');
const mongoose = require('mongoose');
const Chat = require('./models/message'); // Import Chat model for messages

const app = express();
const port = 8000;

// Create an HTTP server and initialize Socket.IO
const server = http.createServer(app);
const io = socketIO(server);


// Connect to MongoDB
mongoose.connect('mongodb+srv://anuratan:Anuratan%401421@cluster0.0uo5r.mongodb.net/?retryWrites=true&w=majority', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB for Socket.IO'))
.catch(error => console.log('Error connecting to MongoDB:', error));

// Handle Socket.IO connections
io.on('connection', (socket) => {
  console.log('A user connected:', socket.id);

  socket.on('sendMessage', async (data) => {
    try {
      const { senderId, receiverId, message, imageUrl } = data;

      // Create a new message instance and save it to the database
      const newMessage = new Chat({ senderId, receiverId, message, imageUrl });
      await newMessage.save();

      // Emit the message to the receiver
      socket.to(receiverId).emit('receiveMessage', newMessage);
      console.log('Message sent successfully:', newMessage);
    } catch (error) {
      console.error('Error handling the message:', error);
    }
  });

  socket.on('disconnect', () => {
    console.log('A user disconnected:', socket.id);
  });
});

// Start the Socket.IO server
server.listen(port, () => {
  console.log(`Socket.IO server running on port ${port}`);
});
