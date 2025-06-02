const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
require('dotenv').config();

const app = express();
const PORT = process.env.PORT || 8000;

// Enhanced CORS configuration for Railway
app.use(cors({
  origin: [
    /^https:\/\/.*\.vercel\.app$/,  // Vercel deployments
    /^https:\/\/.*\.netlify\.app$/,  // Netlify deployments
    /^https:\/\/.*\.railway\.app$/,  // Railway deployments
    'http://localhost:3000',
    'http://127.0.0.1:3000',
    'http://localhost:5500',
    'http://127.0.0.1:5500',
    'http://localhost:8000',
    'http://127.0.0.1:8000',
    // Add specific domains
    process.env.FRONTEND_URL,
    // Development origins
    /^http:\/\/localhost:\d+$/,
    /^http:\/\/127\.0\.0\.1:\d+$/
  ].filter(Boolean), // Remove undefined values
  credentials: true,
  methods: ['GET', 'POST', 'PUT', 'DELETE', 'OPTIONS'],
  allowedHeaders: [
    'Content-Type', 
    'Authorization', 
    'X-Requested-With',
    'Accept',
    'Origin'
  ],
  preflightContinue: false,
  optionsSuccessStatus: 200
}));

// Add explicit preflight handling
app.options('*', cors());

// Enhanced middleware
app.use(express.json({ limit: '10mb' }));
app.use(express.urlencoded({ extended: true, limit: '10mb' }));

// Request logging for development
if (process.env.NODE_ENV !== 'production') {
  app.use((req, res, next) => {
    console.log(`${new Date().toISOString()} - ${req.method} ${req.path}`);
    next();
  });
}

// Health check endpoints (important for Railway)
app.get('/', (req, res) => {
  res.json({ 
    success: true, 
    message: 'Cobblemon Bingo API is running on Railway',
    timestamp: new Date().toISOString(),
    environment: process.env.NODE_ENV || 'development',
    version: '1.0.0'
  });
});

app.get('/health', (req, res) => {
  const healthCheck = {
    success: true,
    message: 'Server is healthy',
    timestamp: new Date().toISOString(),
    uptime: process.uptime(),
    memory: process.memoryUsage(),
    database: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected'
  };
  
  res.json(healthCheck);
});

app.get("/ping", (req, res) => {
  res.status(200).json({ 
    success: true, 
    message: "pong",
    timestamp: new Date().toISOString()
  });
});

// MongoDB Connection with enhanced error handling
const MONGODB_URI = process.env.MONGODB_URI || 'mongodb://localhost:27017/cobblemon-bingo';

// Connection options optimized for Railway/cloud deployment
const mongooseOptions = {
  useNewUrlParser: true,
  useUnifiedTopology: true,
  serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
  socketTimeoutMS: 45000, // Close sockets after 45s of inactivity
  maxPoolSize: 10, // Maintain up to 10 socket connections
  minPoolSize: 1, // Maintain at least 1 socket connection
  maxIdleTimeMS: 30000, // Close connections after 30s of inactivity
  bufferCommands: false, // Disable mongoose buffering
  bufferMaxEntries: 0, // Disable mongoose buffering
  retryWrites: true,
  retryReads: true
};

mongoose.connect(MONGODB_URI, mongooseOptions)
.then(() => {
  console.log('✅ Connected to MongoDB');
  console.log(`📁 Database: ${MONGODB_URI.includes('mongodb.net') ? 'MongoDB Atlas' : 'Local MongoDB'}`);
})
.catch(err => {
  console.error('❌ MongoDB connection error:', err);
  // Don't exit in production, let Railway restart the service
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

// Enhanced connection event handlers
mongoose.connection.on('error', (err) => {
  console.error('❌ MongoDB connection error:', err);
});

mongoose.connection.on('disconnected', () => {
  console.log('⚠️ MongoDB disconnected');
});

mongoose.connection.on('reconnected', () => {
  console.log('✅ MongoDB reconnected');
});

// Schema for Bingo Cards with enhanced indexing
const bingoCardSchema = new mongoose.Schema({
  code: {
    type: String,
    required: true,
    unique: true,
    index: true,
    uppercase: true,
    validate: {
      validator: function(v) {
        return /^CB[0-9A-HJ-NP-Z]{6}$/.test(v);
      },
      message: 'Invalid code format'
    }
  },
  cardData: {
    difficulty: {
      type: String,
      trim: true
    },
    pokemon: [{
      name: {
        type: String,
        required: true,
        trim: true
      },
      id: {
        type: String,
        trim: true
      },
      rarity: {
        type: String,
        trim: true
      },
      biome: {
        type: String,
        trim: true
      }
    }]
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 2592000, // 30 days TTL
    index: true
  },
  usageCount: {
    type: Number,
    default: 0,
    min: 0
  },
  lastAccessed: {
    type: Date,
    default: Date.now
  }
});

// Add compound index for better performance
bingoCardSchema.index({ createdAt: -1, usageCount: -1 });

const BingoCard = mongoose.model('BingoCard', bingoCardSchema);

// Helper function to generate unique codes
function generateUniqueCode() {
  const chars = '0123456789ABCDEFGHJKLMNPQRSTUVWXYZ'; // Removed confusing characters
  let code = 'CB';
  for (let i = 0; i < 6; i++) {
    code += chars.charAt(Math.floor(Math.random() * chars.length));
  }
  return code;
}

// API Routes with enhanced error handling

// Generate and store a new bingo card
app.post('/api/generate-card', async (req, res) => {
  try {
    const { difficulty, pokemon } = req.body;

    // Enhanced validation
    if (!pokemon || !Array.isArray(pokemon)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid pokemon data. Expected array of pokemon.' 
      });
    }

    if (pokemon.length !== 25) {
      return res.status(400).json({ 
        success: false,
        error: `Invalid pokemon count. Expected 25, received ${pokemon.length}.` 
      });
    }

    // Validate pokemon structure
    const invalidPokemon = pokemon.find(p => !p.name || typeof p.name !== 'string');
    if (invalidPokemon) {
      return res.status(400).json({ 
        success: false,
        error: 'All pokemon must have a valid name.' 
      });
    }

    // Generate unique code with better retry logic
    let code;
    let isUnique = false;
    let attempts = 0;
    const maxAttempts = 20;

    while (!isUnique && attempts < maxAttempts) {
      code = generateUniqueCode();
      try {
        const existing = await BingoCard.findOne({ code }).lean();
        if (!existing) {
          isUnique = true;
        }
      } catch (dbErr) {
        console.error('Database error during code generation:', dbErr);
        attempts++;
        continue;
      }
      attempts++;
    }

    if (!isUnique) {
      return res.status(500).json({ 
        success: false,
        error: 'Unable to generate unique code. Please try again.' 
      });
    }

    // Create and save the card
    const bingoCard = new BingoCard({
      code,
      cardData: {
        difficulty: difficulty || 'normal',
        pokemon: pokemon.map(p => ({
          name: (p.name || '').trim(),
          id: (p.id || '').trim(),
          rarity: (p.rarity || '').trim(),
          biome: (p.biome || '').trim()
        }))
      }
    });

    await bingoCard.save();

    console.log(`✅ Generated new bingo card: ${code}`);

    res.json({
      success: true,
      code: code,
      message: 'Card generated successfully',
      expiresAt: new Date(Date.now() + 2592000 * 1000) // 30 days from now
    });

  } catch (error) {
    console.error('❌ Error generating card:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error while generating card',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Retrieve a bingo card by code
app.get('/api/get-card/:code', async (req, res) => {
  try {
    // Validate that code parameter exists
    if (!req.params.code) {
      return res.status(400).json({ 
        success: false,
        error: 'Code parameter is required.' 
      });
    }

    const code = req.params.code.toUpperCase().trim();

    // Validate code format
    if (!/^CB[0-9A-HJ-NP-Z]{6}$/.test(code)) {
      return res.status(400).json({ 
        success: false,
        error: 'Invalid code format. Expected format: CB followed by 6 characters.' 
      });
    }

    const bingoCard = await BingoCard.findOne({ code });

    if (!bingoCard) {
      return res.status(404).json({ 
        success: false,
        error: 'Card not found. Please check the code and try again.' 
      });
    }

    // Increment usage count and update last accessed
    bingoCard.usageCount += 1;
    bingoCard.lastAccessed = new Date();
    await bingoCard.save();

    console.log(`📋 Retrieved card: ${code} (usage: ${bingoCard.usageCount})`);

    res.json({
      success: true,
      code: bingoCard.code,
      cardData: bingoCard.cardData,
      createdAt: bingoCard.createdAt,
      usageCount: bingoCard.usageCount,
      lastAccessed: bingoCard.lastAccessed
    });

  } catch (error) {
    console.error('❌ Error retrieving card:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error while retrieving card',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Validate if a code exists
app.get('/api/validate-code/:code', async (req, res) => {
  try {
    // Validate that code parameter exists
    if (!req.params.code) {
      return res.status(400).json({ 
        success: false,
        exists: false,
        error: 'Code parameter is required.' 
      });
    }

    const code = req.params.code.toUpperCase().trim();

    // Validate code format
    if (!/^CB[0-9A-HJ-NP-Z]{6}$/.test(code)) {
      return res.status(400).json({ 
        success: false,
        exists: false,
        error: 'Invalid code format. Expected format: CB followed by 6 characters.' 
      });
    }

    const bingoCard = await BingoCard.findOne({ code }).lean();

    res.json({
      success: true,
      exists: !!bingoCard,
      message: bingoCard ? 'Code is valid' : 'Code not found',
      code: code
    });

  } catch (error) {
    console.error('❌ Error validating code:', error);
    res.status(500).json({ 
      success: false,
      exists: false,
      error: 'Internal server error while validating code',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get statistics
app.get('/api/stats', async (req, res) => {
  try {
    const [totalCards, recentCards, totalUsage] = await Promise.all([
      BingoCard.countDocuments(),
      BingoCard.countDocuments({
        createdAt: { $gte: new Date(Date.now() - 24 * 60 * 60 * 1000) }
      }),
      BingoCard.aggregate([
        { $group: { _id: null, totalUsage: { $sum: '$usageCount' } } }
      ])
    ]);

    res.json({
      success: true,
      stats: {
        totalCards,
        recentCards,
        totalUsage: totalUsage[0]?.totalUsage || 0,
        serverUptime: process.uptime(),
        timestamp: new Date().toISOString()
      }
    });
  } catch (error) {
    console.error('❌ Error getting stats:', error);
    res.status(500).json({ 
      success: false,
      error: 'Internal server error while getting stats',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Enhanced error handling middleware
app.use((err, req, res, next) => {
  console.error('💥 Unhandled error:', err);
  
  // Mongoose validation errors
  if (err.name === 'ValidationError') {
    return res.status(400).json({
      success: false,
      error: 'Validation error',
      details: Object.values(err.errors).map(e => e.message)
    });
  }
  
  // Mongoose duplicate key error
  if (err.code === 11000) {
    return res.status(409).json({
      success: false,
      error: 'Duplicate entry',
      details: 'This code already exists'
    });
  }
  
  res.status(500).json({
    success: false,
    error: 'Internal server error',
    details: process.env.NODE_ENV === 'development' ? err.message : undefined
  });
});

// 404 handler
app.use((req, res) => {
  res.status(404).json({
    success: false,
    error: 'Route not found',
    availableRoutes: [
      'GET /',
      'GET /health',
      'GET /ping',
      'POST /api/generate-card',
      'GET /api/get-card/:code',
      'GET /api/validate-code/:code',
      'GET /api/stats'
    ]
  });
});

// Start server
const server = app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 Server running on port ${PORT}`);
  console.log(`🌍 Environment: ${process.env.NODE_ENV || 'development'}`);
  console.log(`📊 MongoDB URI: ${MONGODB_URI.replace(/\/\/.*@/, '//***:***@')}`);
  console.log(`🎯 API Base URL: http://localhost:${PORT}`);
});

// Enhanced graceful shutdown
const gracefulShutdown = (signal) => {
  console.log(`\n⚠️ ${signal} received, shutting down gracefully...`);
  
  server.close(() => {
    console.log('✅ HTTP server closed');
    
    mongoose.connection.close(false, () => {
      console.log('✅ MongoDB connection closed');
      console.log('👋 Process terminated');
      process.exit(0);
    });
  });
  
  // Force close after 10 seconds
  setTimeout(() => {
    console.error('❌ Could not close connections in time, forcefully shutting down');
    process.exit(1);
  }, 10000);
};

process.on('SIGTERM', () => gracefulShutdown('SIGTERM'));
process.on('SIGINT', () => gracefulShutdown('SIGINT'));

// Handle unhandled promise rejections
process.on('unhandledRejection', (reason, promise) => {
  console.error('💥 Unhandled Rejection at:', promise, 'reason:', reason);
  // Don't exit in production, let Railway handle restarts
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});

// Handle uncaught exceptions
process.on('uncaughtException', (error) => {
  console.error('💥 Uncaught Exception:', error);
  // Don't exit in production, let Railway handle restarts
  if (process.env.NODE_ENV !== 'production') {
    process.exit(1);
  }
});
