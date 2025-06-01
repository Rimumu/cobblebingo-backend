const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const crypto = require('crypto');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 3000;

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static('public')); // Serve your HTML, CSS, JS files from 'public' folder

// MongoDB Connection
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cobblemon-bingo';

mongoose.connect(MONGODB_URI, {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// Schema for Bingo Cards
const bingoCardSchema = new mongoose.Schema({
  code: {
    type: String,
    required: true,
    unique: true,
    index: true
  },
  cardData: {
    difficulty: String,  // Changed from rarity to difficulty
    pokemon: [{
      name: String,
      id: String,
      rarity: String,
      biome: String
    }]
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 2592000 // 30 days TTL (Time To Live)
  },
  usageCount: {
    type: Number,
    default: 0
  }
});

const BingoCard = mongoose.model('BingoCard', bingoCardSchema);

// Helper function to generate unique codes
function generateUniqueCode() {
  const chars = '0123456789ABCDEFGHJKLMNPQRSTUVWXYZ';
  let code = 'CB';
  for (let i = 0; i < 6; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

// API Routes

// Generate and store a new bingo card
app.post('/api/generate-card', async (req, res) => {
  try {
    const { difficulty, pokemon } = req.body;  // Changed from rarity to difficulty

    if (!pokemon || !Array.isArray(pokemon) || pokemon.length !== 25) {
      return res.status(400).json({ 
        error: 'Invalid pokemon data. Expected array of 25 pokemon.' 
      });
    }

    // Generate unique code
    let code;
    let isUnique = false;
    let attempts = 0;
    const maxAttempts = 10;

    while (!isUnique && attempts < maxAttempts) {
      code = generateUniqueCode();
      const existing = await BingoCard.findOne({ code });
      if (!existing) {
        isUnique = true;
      }
      attempts++;
    }

    if (!isUnique) {
      return res.status(500).json({ 
        error: 'Unable to generate unique code. Please try again.' 
      });
    }

    // Create and save the card
    const bingoCard = new BingoCard({
      code,
      cardData: {
        difficulty: difficulty || '',  // Changed from rarity to difficulty
        pokemon: pokemon.map(p => ({
          name: p.name || '',
          id: p.id || '',
          rarity: p.rarity || '',
          biome: p.biome || ''
        }))
      }
    });

    await bingoCard.save();

    res.json({
      success: true,
      code: code,
      message: 'Card generated successfully'
    });

  } catch (error) {
    console.error('Error generating card:', error);
    res.status(500).json({ 
      error: 'Internal server error while generating card' 
    });
  }
});

// Retrieve a bingo card by code
app.get('/api/get-card/:code', async (req, res) => {
  try {
    const code = req.params.code.toUpperCase();

    // Validate code format
    if (!/^CB[0-9A-HJ-NP-Z]{6}$/.test(code)) {
      return res.status(400).json({ 
        error: 'Invalid code format' 
      });
    }

    const bingoCard = await BingoCard.findOne({ code });

    if (!bingoCard) {
      return res.status(404).json({ 
        error: 'Card not found' 
      });
    }

    // Increment usage count
    bingoCard.usageCount += 1;
    await bingoCard.save();

    res.json({
      success: true,
      code: bingoCard.code,
      cardData: bingoCard.cardData,
      createdAt: bingoCard.createdAt,
      usageCount: bingoCard.usageCount
    });

  } catch (error) {
    console.error('Error retrieving card:', error);
    res.status(500).json({ 
      error: 'Internal server error while retrieving card' 
    });
  }
});

// Validate if a code exists
app.get('/api/validate-code/:code', async (req, res) => {
  try {
    const code = req.params.code.toUpperCase();

    // Validate code format
    if (!/^CB[0-9A-HJ-NP-Z]{6}$/.test(code)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid code format' 
      });
    }

    const bingoCard = await BingoCard.findOne({ code });

    res.json({
      success: true,
      exists: !!bingoCard,
      message: bingoCard ? 'Code is valid' : 'Code not found'
    });

  } catch (error) {
    console.error('Error validating code:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error while validating code' 
    });
  }
});

// Get statistics (optional)
app.get('/api/stats', async (req, res) => {
  try {
    const totalCards = await BingoCard.countDocuments();
    const recentCards = await BingoCard.countDocuments({
      createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
    });

    res.json({
      success: true,
      stats: {
        totalCards,
        recentCards
      }
    });
  } catch (error) {
    console.error('Error getting stats:', error);
    res.status(500).json({ 
      error: 'Internal server error while getting stats' 
    });
  }
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Server is running',
    timestamp: new Date().toISOString()
  });
});

// Start server
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Environment: ${process.env.NODE_ENV || 'development'}`);
});

app.get("/ping", (req, res) => {
  res.status(200).send("OK");
});