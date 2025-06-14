const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const { v4: uuidv4 } = require('uuid'); // For generating session IDs
require('dotenv').config();
const bcrypt = require('bcryptjs'); 
const jwt = require('jsonwebtoken');
const { expressjwt: jwtAuth } = require('express-jwt'); // Add this for JWT middleware
const fetch = require('node-fetch'); // Or use another request library like axios
const { URLSearchParams } = require('url');
const fs = require('fs'); // Import the File System module
const path = require('path'); // Import the Path module
const { Rcon } = require('rcon-client'); // Import the RCON client
const app = express();
const PORT = process.env.PORT || 8000;

// --- Load Gacha Configuration from JSON file ---
let packContents = {};
try {
    const gachaConfigPath = path.join(__dirname, 'gacha-config.json');
    const gachaConfigFile = fs.readFileSync(gachaConfigPath, 'utf8');
    packContents = JSON.parse(gachaConfigFile).packContents;
    console.log('✅ Gacha configuration loaded successfully.');
} catch (error) {
    console.error('❌ Failed to load gacha-config.json:', error);
    // Exit if the config is essential for the server to run
    process.exit(1);
}


// --- 1. ADD a master list of rewardable items. Place this near the top with other definitions. ---
const rewardableItems = [
    { itemId: 'kitchen_knife', itemName: 'Kitchen Knife', image: 'https://i.imgur.com/2khorfF.png' },
    { itemId: 'chef_knife', itemName: 'Chef Knife', image: 'https://i.imgur.com/HDRGq9Y.png' },
    // You can add any future items here
];
// --- ADD JWT Middleware for protected routes ---
const authMiddleware = jwtAuth({
  secret: process.env.JWT_SECRET || 'your_default_jwt_secret',
  algorithms: ['HS256'],
  requestProperty: 'auth',
  getToken: function fromHeaderOrQuerystring(req) {
    // This function tells the middleware to look for the token in two places:
    // 1. In the standard Authorization header (for API calls)
    if (req.headers.authorization && req.headers.authorization.split(' ')[0] === 'Bearer') {
      return req.headers.authorization.split(' ')[1];
    } 
    // 2. In the URL query string (for link clicks like this one)
    else if (req.query && req.query.token) {
      return req.query.token;
    }
    return null; // No token found
  }
});

// --- ADD NEW Admin-only Middleware (Place this near your authMiddleware) ---
const adminMiddleware = async (req, res, next) => {
    try {
        const user = await User.findById(req.auth.user.id);
        if (user && user.isAdmin) {
            next(); // User is an admin, proceed
        } else {
            res.status(403).json({ success: false, error: 'Forbidden: Admin access required.' });
        }
    } catch (error) {
        res.status(500).json({ success: false, error: 'Server error during admin check.' });
    }
};

// --- START: New Helper Function to Send Discord Webhook ---
// Place this function near the top with other helper functions.
async function sendDiscordAnnouncement(payload) {
    const webhookUrl = process.env.DISCORD_ANNOUNCEMENT_WEBHOOK_URL;
    if (!webhookUrl) {
        console.warn('⚠️ DISCORD_ANNOUNCEMENT_WEBHOOK_URL not set. Skipping announcement.');
        return;
    }

    try {
        await fetch(webhookUrl, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify(payload),
        });
        console.log(`📢 Sent Discord announcement for: ${payload.embeds[0].title}`);
    } catch (error) {
        console.error('❌ Failed to send Discord webhook announcement:', error);
    }
}
// --- END: New Helper Function ---


// Enhanced CORS configuration for Railway
app.use(cors({
  origin: [
    /^https:\/\/.*\.vercel\.app$/,  // Vercel deployments
    /^https:\/\/.*\.netlify\.app$/,  // Netlify deployments
    /^https:\/\/.*\.railway\.app$/,  // Railway deployments
    /^https:\/\/.*\.greatrimu\.cloud$/,  // Your custom domain
    'https://cobblebingo.greatrimu.cloud',  // Specific frontend domain
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
  serverSelectionTimeoutMS: 5000, // Timeout after 5s instead of 30s
  socketTimeoutMS: 45000, // Close sockets after 45s of inactivity
  maxPoolSize: 10, // Maintain up to 10 socket connections
  minPoolSize: 1, // Maintain at least 1 socket connection
  maxIdleTimeMS: 30000, // Close connections after 30s of inactivity
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

// Schema for Bingo Sessions
const bingoSessionSchema = new mongoose.Schema({
  sessionId: {
    type: String,
    required: true,
    unique: true,
    index: true,
  },
  cardCode: { // To link the session to a specific bingo card
    type: String,
    required: true,
    index: true,
    uppercase: true,
  },
  completedCells: {
    type: [Boolean],
    default: () => Array(25).fill(false), // Stores the state of each of the 25 cells
    validate: {
      validator: function(v) {
        return Array.isArray(v) && v.length === 25 && v.every(val => typeof val === 'boolean');
      },
      message: 'Completed cells must be an array of 25 booleans.'
    }
  },
  createdAt: {
    type: Date,
    default: Date.now,
    expires: 2592000, // 30 days TTL, same as cards
    index: true
  },
  userId: { // Add this to link session to a user
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    index: true,
    default: null
  },
  isSaved: { // Add this field
    type: Boolean,
    default: false,
    index: true
  },
  sessionName: { // Add this field
    type: String,
    trim: true,
    default: null
  },
  lastAccessed: {
    type: Date,
    default: Date.now
  }
});

// Add compound index for querying sessions by cardCode
bingoSessionSchema.index({ cardCode: 1, lastAccessed: -1 });

// ***** THIS LINE MUST COME BEFORE generateUniqueSessionId *****
const BingoSession = mongoose.model('BingoSession', bingoSessionSchema);
// ***** AND ALSO BEFORE ANY OTHER USE OF BingoSession *********

// --- ADD NEW USER SCHEMA after BingoSession Schema ---
const userSchema = new mongoose.Schema({
  username: {
    type: String,
    required: true,
    unique: true,
    trim: true,
    minlength: 3,
    maxlength: 20,
    match: /^[a-zA-Z0-9_]+$/ // Alphanumeric and underscores only
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  discordId: {
    type: String,
    unique: true,
    sparse: true, // This allows multiple users to have a null value
    default: null
  },
  discordUsername: {
    type: String,
    default: null
  },
  inventory: [{
    itemId: { type: String, required: true },
    itemName: { type: String, required: true },
    quantity: { type: Number, required: true, default: 1 },
    image: { type: String, default: null },
    id: { type: String, default: null } // For Pokemon ID
  }],
  isAdmin: {
        type: Boolean,
        default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) {
    return next();
  }
  const salt = await bcrypt.genSalt(10);
  this.password = await bcrypt.hash(this.password, salt);
  next();
});

const User = mongoose.model('User', userSchema);

// --- ADD NEW SCHEMA for Redeem Codes (Place this near your other schemas) ---
const redeemCodeSchema = new mongoose.Schema({
    code: {
        type: String,
        required: true,
        unique: true,
        uppercase: true,
        trim: true
    },
    reward: {
        itemId: { type: String, required: true },
        itemName: { type: String, required: true },
        quantity: { type: Number, required: true, default: 1 },
        image: { type: String, required: true } // Add the image field
    },
    useType: {
        type: String,
        enum: ['one-time', 'one-time-per-user', 'infinite'], 
        default: 'one-time'
    },
    usersWhoRedeemed: [{
        type: mongoose.Schema.Types.ObjectId,
        ref: 'User'
    }],
    createdAt: {
        type: Date,
        default: Date.now
    }
});
const RedeemCode = mongoose.model('RedeemCode', redeemCodeSchema);

// --- Pre-process packContents to generate Cobbledex URLs for Pokémon ---
for (const packId in packContents) {
    packContents[packId].forEach(item => {
        if (item.itemId.startsWith('pokemon_') && !item.image) {
            const formattedName = item.itemName.toLowerCase().replace(/\s+/g, "_");
            item.image = `https://cobbledex.b-cdn.net/mons/large/${formattedName}.webp`;
        }
    });
}


// --- Create a single source of truth for all item details ---
const allItemsMap = new Map();
// Add items from rewardableItems
rewardableItems.forEach(item => allItemsMap.set(item.itemId, item));
// Add items from packContents, without overwriting
Object.values(packContents).flat().forEach(item => {
    if (!allItemsMap.has(item.itemId)) {
        allItemsMap.set(item.itemId, item);
    }
});

// --- Create a reusable enrichment function ---
function enrichInventory(inventory) {
    if (!inventory || !Array.isArray(inventory)) return [];
    return inventory.map(invItem => {
        // Mongoose subdocuments need to be converted to plain objects to be modified
        const enrichedItem = invItem.toObject ? invItem.toObject() : { ...invItem };
        
        if (!enrichedItem.image) {
            const details = allItemsMap.get(enrichedItem.itemId);
            if (details) {
                enrichedItem.image = details.image;
            }
        }
        // Ensure image is at least an empty string to prevent .includes error on null
        if (enrichedItem.image === null || enrichedItem.image === undefined) {
             enrichedItem.image = '';
        }
        return enrichedItem;
    });
}


// Helper function to generate unique session IDs (using uuid)
async function generateUniqueSessionId() {
  let sessionId;
  let isUnique = false;
  let attempts = 0;
  const maxAttempts = 10; // Reduced attempts as UUIDs are highly unique

  while (!isUnique && attempts < maxAttempts) {
    sessionId = `SESS-${uuidv4()}`; // Example prefix
    try {
      const existing = await BingoSession.findOne({ sessionId }).lean();
      if (!existing) {
        isUnique = true;
      }
    } catch (dbErr) {
      console.error('Database error during session ID generation:', dbErr);
      // Potentially retry or handle error
    }
    attempts++;
  }

  if (!isUnique) {
    throw new Error('Unable to generate unique session ID.');
  }
  return sessionId;
}

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

// --- ADD NEW AUTHENTICATION API ROUTES ---
const authRouter = express.Router();
// --- ADD NEW ADMIN ROUTES (Place these at the end of your API routes) ---
const adminRouter = express.Router();

// SIGNUP
authRouter.post('/signup', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password are required.' });
    }
    if (password.length < 6) {
        return res.status(400).json({ success: false, error: 'Password must be at least 6 characters long.' });
    }

    let user = await User.findOne({ username });
    if (user) {
      return res.status(409).json({ success: false, error: 'Username already exists.' });
    }

    user = new User({ username, password });
    await user.save();

    res.status(201).json({ success: true, message: 'User created successfully.' });
  } catch (error) {
    console.error('❌ Error during signup:', error);
    res.status(500).json({ success: false, error: 'Server error during signup.' });
  }
});

// LOGIN
authRouter.post('/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    if (!username || !password) {
      return res.status(400).json({ success: false, error: 'Username and password are required.' });
    }

    const user = await User.findOne({ username });
    if (!user) {
      return res.status(401).json({ success: false, error: 'Invalid credentials.' });
    }

    const isMatch = await bcrypt.compare(password, user.password);
    if (!isMatch) {
      return res.status(401).json({ success: false, error: 'Invalid credentials.' });
    }

    const payload = {
      user: {
        id: user.id,
        username: user.username
      }
    };

    const token = jwt.sign(
      payload,
      process.env.JWT_SECRET || 'your_default_jwt_secret',
      { expiresIn: '7d' }
    );
    res.json({ success: true, token });
    
  } catch (error) {
    console.error('❌ Error during login:', error);
    res.status(500).json({ success: false, error: 'Server error during login.' });
  }
});

// Mount the auth router
app.use('/api/auth', authRouter);

const optionalAuth = (req, res, next) => {
    // This is a simple version. A more robust solution might use a library.
    const token = req.headers.authorization?.split(' ')[1];
    if (!token) return next();

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your_default_jwt_secret');
        req.auth = decoded; // Attach user payload to request
    } catch (err) {
        // Invalid token, just ignore and proceed as anonymous
    }
    next();
};

app.get('/api/auth/discord', authMiddleware, (req, res) => {
    const discordAuthUrl = `https://discord.com/api/oauth2/authorize` +
        `?client_id=${process.env.DISCORD_CLIENT_ID}` +
        `&redirect_uri=${encodeURIComponent(process.env.DISCORD_REDIRECT_URI)}` +
        `&response_type=code` +
        `&scope=identify` + // 'identify' scope gets user info without joining servers
        `&state=${req.auth.user.id}`; // Pass the user's ID to identify them on callback

    res.redirect(discordAuthUrl);
});

// Discord redirects the user here after they authorize.
app.get('/api/auth/discord/callback', async (req, res) => {
    const { code, state: userId } = req.query;

    if (!code) {
        return res.status(400).send("Error: Discord callback code not found.");
    }

    try {
        // ... (The code to exchange the token and get user info remains the same)
        const tokenResponse = await fetch('https://discord.com/api/oauth2/token', {
            method: 'POST',
            body: new URLSearchParams({
                client_id: process.env.DISCORD_CLIENT_ID,
                client_secret: process.env.DISCORD_CLIENT_SECRET,
                grant_type: 'authorization_code',
                code,
                redirect_uri: process.env.DISCORD_REDIRECT_URI,
            }),
            headers: {
                'Content-Type': 'application/x-www-form-urlencoded',
            },
        });

        const tokenData = await tokenResponse.json();
        if (tokenData.error) {
            throw new Error(`Discord token error: ${tokenData.error_description}`);
        }

        const userResponse = await fetch('https://discord.com/api/users/@me', {
            headers: {
                authorization: `${tokenData.token_type} ${tokenData.access_token}`,
            },
        });
        const discordUser = await userResponse.json();

        const user = await User.findById(userId);
        if (!user) {
            return res.status(404).send("Error: User to link not found.");
        }

        user.discordId = discordUser.id;
        // --- THIS IS THE CORRECTED LINE ---
        user.discordUsername = discordUser.username; // No more hashtag and discriminator
        await user.save();

        const frontendUrl = process.env.FRONTEND_URL || 'http://localhost:5500';
        res.redirect(`${frontendUrl}?discord_linked=true`);

    } catch (error) {
        console.error("Error in Discord OAuth callback:", error);
        res.status(500).send("An error occurred while linking your Discord account.");
    }
});

app.get('/api/user/me', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.auth.user.id).select('-password');
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found.' });
        }

        let inventoryModified = false;
        
        const validInventory = user.inventory.filter(item => allItemsMap.has(item.itemId));

        if (validInventory.length !== user.inventory.length) {
            inventoryModified = true;
        }

        const syncedInventory = validInventory.map(item => {
            const masterItem = allItemsMap.get(item.itemId);
            if (item.itemName !== masterItem.itemName || item.image !== masterItem.image) {
                inventoryModified = true;
            }
            return {
                ...item.toObject(),
                itemName: masterItem.itemName,
                image: masterItem.image,
                id: masterItem.id || null, 
            };
        });

        if (inventoryModified) {
            user.inventory = syncedInventory;
            await user.save();
            console.log(`✅ Synced and cleaned inventory for user: ${user.username} during /me fetch`);
        }
        
        const userObject = user.toObject();
        userObject.inventory = enrichInventory(userObject.inventory);

        res.json({ success: true, user: userObject });
    } catch (error) {
        console.error("Error fetching user data:", error);
        res.status(500).json({ success: false, error: 'Server error while fetching user data.' });
    }
});


app.post('/api/auth/discord/unlink', authMiddleware, async (req, res) => {
    try {
        const user = await User.findById(req.auth.user.id);
        if (!user) {
            return res.status(404).json({ success: false, error: 'User not found.' });
        }

        // Clear the Discord-related fields
        user.discordId = null;
        user.discordUsername = null;
        await user.save();

        res.json({ success: true, message: 'Discord account unlinked successfully.' });
    } catch (error) {
        console.error("Error unlinking discord account:", error);
        res.status(500).json({ success: false, error: 'Server error while unlinking account.' });
    }
});

// NEW Route to get the list of possible reward items
adminRouter.get('/reward-items', (req, res) => {
    res.json({ success: true, items: rewardableItems });
});

// Generate a new redeem code
adminRouter.post('/generate-code', async (req, res) => {
    // The form now only sends itemId, quantity, etc.
    const { code, itemId, quantity, useType } = req.body;
    if (!code || !itemId || !quantity || !useType) {
        return res.status(400).json({ success: false, error: 'Missing required fields.' });
    }
    try {
        // Find the full item details from our master list
        const itemDetails = rewardableItems.find(item => item.itemId === itemId);
        if (!itemDetails) {
            return res.status(404).json({ success: false, error: 'Invalid reward item ID selected.' });
        }

        const newCode = new RedeemCode({
            code,
            reward: {
                itemId: itemDetails.itemId,
                itemName: itemDetails.itemName,
                image: itemDetails.image, // Get the image from our master list
                quantity: quantity
            },
            useType
        });
        await newCode.save();
        res.status(201).json({ success: true, message: 'Code generated successfully.', code: newCode });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Could not generate code.', details: error.message });
    }
});

// Get all existing codes
adminRouter.get('/codes', async (req, res) => {
    try {
        const codes = await RedeemCode.find().sort({ createdAt: -1 });
        res.json({ success: true, codes });
    } catch (error) {
        res.status(500).json({ success: false, error: 'Could not fetch codes.' });
    }
});

// Mount the admin router with double protection
app.use('/api/admin', authMiddleware, adminMiddleware, adminRouter);


// --- ADD NEW Redeem Code Route (Place this near other public API routes) ---
app.post('/api/redeem', authMiddleware, async (req, res) => {
    const { code } = req.body;
    const userId = req.auth.user.id;

    if (!code) {
        return res.status(400).json({ success: false, error: 'Please enter a code.' });
    }

    try {
        const redeemCode = await RedeemCode.findOne({ code: code.toUpperCase() });

        if (!redeemCode) {
            return res.status(404).json({ success: false, error: 'Invalid code.' });
        }

        // --- FIX 1: Correctly check if user has redeemed a 'one-time-per-user' code ---
        if (redeemCode.useType === 'one-time' && redeemCode.usersWhoRedeemed.length > 0) {
            return res.status(403).json({ success: false, error: 'This code has already been redeemed.' });
        }
        if (redeemCode.useType === 'one-time-per-user' && redeemCode.usersWhoRedeemed.some(id => id.equals(userId))) {
            return res.status(403).json({ success: false, error: 'You have already redeemed this code.' });
        }

        const user = await User.findById(userId);
        const itemInInventory = user.inventory.find(item => item.itemId === redeemCode.reward.itemId);

        if (itemInInventory) {
            itemInInventory.quantity += redeemCode.reward.quantity;
        } else {
            user.inventory.push(redeemCode.reward);
        }
        await user.save();

        // --- FIX 2: Always track the redemption to count infinite codes correctly ---
        redeemCode.usersWhoRedeemed.push(userId);
        await redeemCode.save();
        
        res.json({ success: true, message: `Successfully redeemed! You received: ${redeemCode.reward.quantity}x ${redeemCode.reward.itemName}` });

    } catch (error) {
        console.error("Redeem Error:", error);
        res.status(500).json({ success: false, error: 'An error occurred during redemption.' });
    }
});

// --- API Endpoint to use an item from inventory ---
app.post('/api/inventory/use', authMiddleware, async (req, res) => {
    const { itemId } = req.body;
    const userId = req.auth.user.id;

    if (!itemId) {
        return res.status(400).json({ success: false, error: 'itemId is required.' });
    }

    let rcon;
    try {
        const user = await User.findById(userId);
        const itemInInventory = user.inventory.find(item => item.itemId === itemId);

        if (!itemInInventory || itemInInventory.quantity <= 0) {
            return res.status(404).json({ success: false, error: "Item not found in inventory or quantity is zero." });
        }

        const itemDetails = allItemsMap.get(itemId);
        if (!itemDetails || !itemDetails.command) {
            return res.status(400).json({ success: false, error: "This item is not usable." });
        }

        // Connect to RCON
        rcon = await Rcon.connect({
            host: process.env.RCON_HOST,
            port: process.env.RCON_PORT,
            password: process.env.RCON_PASSWORD,
        });

        // First, check if the player is online
        const listResponse = await rcon.send('list');
        if (!listResponse.includes(user.username)) {
            // If player is not online, send specific error and do not consume the item
            return res.status(400).json({
                success: false,
                error: 'Player is not online.',
                errorCode: 'PLAYER_OFFLINE'
            });
        }
        
        // If player is online, proceed to give the item
        const command = itemDetails.command.replace('{player}', user.username);
        await rcon.send(command);
        console.log(`RCON command sent for ${user.username}: "${command}".`);

        // If command was successful, decrement item quantity and save user
        itemInInventory.quantity -= 1;
        if (itemInInventory.quantity <= 0) {
            user.inventory = user.inventory.filter(item => item.itemId !== itemId);
        }
        await user.save();
        
        // Send back the updated and enriched inventory
        const finalInventory = enrichInventory(user.inventory);

        res.json({
            success: true,
            message: `${itemDetails.itemName} has been redeemed in-game!`,
            newInventory: finalInventory
        });

    } catch (error) {
        console.error("Error using item:", error);
        res.status(500).json({ success: false, error: 'Failed to use item. Check server connection and try again.' });
    } finally {
        // Ensure the RCON connection is always closed
        if (rcon) {
            await rcon.end();
        }
    }
});


// --- GACHA SYSTEM LOGIC ---

// Define the available banners on the server
const gachaBanners = [
    {
        id: 'lamb_chop_pack',
        name: 'Lamb Chop Pack',
        description: 'A hearty pack with a chance to contain delicious and common Pokémon.',
        image: 'https://placehold.co/800x450/663300/FFFFFF?text=Lamb+Chop+Pack&font=georgia',
        featuring: ["Shiny Arceus"],
        requiredItemId: 'kitchen_knife'
    },
    {
        id: 'a5_wagyu_pack',
        name: 'A5 Wagyu Pack',
        description: 'An exquisite and rare pack with a chance to contain the most legendary and flavorful Pokémon.',
        image: 'https://placehold.co/800x450/990000/FFFFFF?text=A5+Wagyu+Pack&font=playfair+display',
        featuring: ["Shiny Mew", "Shaymin"],
        requiredItemId: 'chef_knife'
    }
];


// --- NEW Helper function to generate the full animation reel ---
// *** MODIFICATION START: Accept loot table instead of packId ***
function generateAnimationReel(lootTable, winningItem) {
    if (!lootTable) return [];
// *** MODIFICATION END ***

    let reelItems = [];
    const reelLength = 80;
    const winningIndex = 70;

    for (let i = 0; i < reelLength; i++) {
        if (i === winningIndex) {
            reelItems.push(winningItem);
        } else {
            reelItems.push(lootTable[Math.floor(Math.random() * lootTable.length)]);
        }
    }
    return reelItems;
}

app.get('/api/gacha/banners', (req, res) => {
    const enrichedBanners = gachaBanners.map(banner => {
        const requiredItemDetails = allItemsMap.get(banner.requiredItemId);
        return {
            ...banner,
            requiredItem: requiredItemDetails || {
                itemId: banner.requiredItemId,
                itemName: banner.requiredItemId,
                image: ''
            }
        };
    });
    res.json({ success: true, banners: enrichedBanners });
});


// --- Gacha Announcement Endpoint ---
app.post('/api/gacha/announce-pull', authMiddleware, async (req, res) => {
    try {
        const { itemId } = req.body;
        const userId = req.auth.user.id;

        if (!itemId) {
            return res.status(400).json({ success: false, error: 'itemId is required.' });
        }

        const user = await User.findById(userId);
        const itemDetails = { ...allItemsMap.get(itemId) }; 

        if (!user || !itemDetails) {
            return res.status(404).json({ success: false, error: 'User or item not found.' });
        }
        
        const rarityColors = {
            common: 9807270,      
            uncommon: 8311585,    
            rare: 3447003,        
            epic: 10181046,       
            legendary: 15844367,  
            mythic: 15158332,     
        };
        
        const isPokemon = itemDetails.itemId.startsWith('pokemon_');
        
        // Re-implementing the Cobbledex fallback logic
        if (isPokemon) {
            const isShiny = itemDetails.itemName.toLowerCase().includes('shiny');
            const shinyPrefix = isShiny ? 'shiny/' : '';
            const pokeapiUrl = `https://raw.githubusercontent.com/PokeAPI/sprites/master/sprites/pokemon/other/official-artwork/${shinyPrefix}${itemDetails.id}.png`;
            const nonShinyName = itemDetails.itemName.replace(/shiny /i, '');
            const cobbledexUrl = `https://cobbledex.b-cdn.net/mons/large/${nonShinyName.toLowerCase().replace(/\s+/g, "_")}.webp`;

            try {
                 const cobbledexResponse = await fetch(cobbledexUrl);
                 if (!cobbledexResponse.ok) throw new Error('Cobbledex URL not OK');

                 const contentLength = cobbledexResponse.headers.get('content-length');
                 const PLACEHOLDER_SIZE_MIN = 2160;
                 const PLACEHOLDER_SIZE_MAX = 2180; 

                if (contentLength && parseInt(contentLength, 10) >= PLACEHOLDER_SIZE_MIN && parseInt(contentLength, 10) <= PLACEHOLDER_SIZE_MAX) {
                     throw new Error("Placeholder image detected from content-length");
                }
                itemDetails.image = cobbledexUrl;
            } catch (e) {
                console.warn(`Could not use Cobbledex for ${itemDetails.itemName} (${e.message}), falling back to PokeAPI.`);
                itemDetails.image = pokeapiUrl;
            }
        }


        let title, description, fieldName;

        if (isPokemon) {
            title = `A wild **${itemDetails.itemName}** appeared!`;
            description = `**${user.username}** just pulled the **${itemDetails.rarity.toUpperCase()}** Pokémon!`;
            fieldName = "Pokémon";
        } else {
            title = `A random **${itemDetails.itemName}** has just appeared!`;
            description = `**${user.username}** just pulled a **${itemDetails.rarity.toUpperCase()}** item!`;
            fieldName = "Item";
        }
        
        const embedObject = {
            title: title,
            description: description,
            color: rarityColors[itemDetails.rarity] || 0,
            fields: [
                { name: fieldName, value: itemDetails.itemName, inline: true },
                { name: "Rarity", value: itemDetails.rarity.charAt(0).toUpperCase() + itemDetails.rarity.slice(1), inline: true },
            ],
            timestamp: new Date().toISOString(),
            footer: {
                text: "Cobblemon Gacha",
            },
        };

        embedObject.image = { url: itemDetails.image };

        const embed = {
            content: `<@${user.discordId}>`, 
            embeds: [embedObject],
        };
        
        await sendDiscordAnnouncement(embed);

        res.status(202).json({ success: true, message: 'Announcement request accepted.' });

    } catch (error) {
        console.error('❌ Error in /api/gacha/announce-pull:', error);
        res.status(500).json({ success: false, error: 'Server error during announcement.' });
    }
});


app.post('/api/gacha/open-pack', authMiddleware, async (req, res) => {
    try {
        const { bannerId } = req.body;
        const userId = req.auth.user.id;

        const banner = gachaBanners.find(b => b.id === bannerId);
        if (!banner) return res.status(404).json({ success: false, error: 'Banner not found.' });

        const user = await User.findById(userId);
        const inventoryItem = user.inventory.find(item => item.itemId === banner.requiredItemId);
        if (!inventoryItem || inventoryItem.quantity < 1) {
            return res.status(400).json({ success: false, error: 'You do not have the required pack.' });
        }

        inventoryItem.quantity -= 1;
        if (inventoryItem.quantity === 0) {
            user.inventory = user.inventory.filter(item => item.itemId !== banner.requiredItemId);
        }

        let lootTable = [...packContents[banner.id]]; 
        const mythicItems = lootTable.filter(item => item.rarity === 'mythic');

        if (mythicItems.length > 1) {
            const nonMythicItems = lootTable.filter(item => item.rarity !== 'mythic');
            
            const totalMythicChance = mythicItems.reduce((sum, item) => sum + (item.mythicChance || 1), 0);
            let randomMythicNum = Math.random() * totalMythicChance;
            let chosenMythic;
            for(const item of mythicItems) {
                const chance = item.mythicChance || 1;
                if (randomMythicNum < chance) {
                    chosenMythic = item;
                    break;
                }
                randomMythicNum -= chance;
            }
            if(!chosenMythic) chosenMythic = mythicItems[0]; 

            lootTable = [...nonMythicItems, chosenMythic];
            console.log(`Adjusted loot table for this opening. Chosen mythic: ${chosenMythic.itemName}`);
        }

        const totalWeight = lootTable.reduce((sum, item) => sum + item.weight, 0);
        let randomNum = Math.random() * totalWeight;
        let reward;
        for (const item of lootTable) {
            if (randomNum < item.weight) {
                reward = item;
                break;
            }
            randomNum -= item.weight;
        }
        if (!reward) {
            reward = lootTable[0];
        }
        
        const rewardInInventory = user.inventory.find(item => item.itemId === reward.itemId);
        if (rewardInInventory) {
            rewardInInventory.quantity += 1;
            rewardInInventory.image = reward.image;
            rewardInInventory.id = reward.id;
        } else {
            user.inventory.push({
                itemId: reward.itemId,
                itemName: reward.itemName,
                quantity: 1,
                image: reward.image,
                id: reward.id
            });
        }
        
        await user.save();

        const animationReelFromServer = generateAnimationReel(lootTable, reward);
        
        const rewardForFrontend = { ...reward, name: reward.itemName };
        const animationReelForFrontend = animationReelFromServer.map(item => ({...item, name: item.itemName}));
        const finalInventory = enrichInventory(user.inventory);
        
        res.json({ success: true, reward: rewardForFrontend, newInventory: finalInventory, animationReel: animationReelForFrontend });

    } catch (error) {
        console.error("Error opening pack:", error);
        res.status(500).json({ success: false, error: 'Server error while opening pack.' });
    }
});

// --- BINGO CARD SYSTEM LOGIC ---
// Create or get a session for a card
app.post('/api/session/init', optionalAuth, async (req, res) => { // Added optionalAuth
  try {
    const { cardCode } = req.body;

    if (!cardCode) {
      return res.status(400).json({ success: false, error: 'cardCode is required.' });
    }

    if (!/^CB[0-9A-HJ-NP-Z]{6}$/.test(cardCode.toUpperCase())) {
        return res.status(400).json({ success: false, error: 'Invalid cardCode format.' });
    }

    const cardExists = await BingoCard.findOne({ code: cardCode.toUpperCase() }).lean();
    if (!cardExists) {
        return res.status(404).json({ success: false, error: 'Associated card not found.' });
    }

    const sessionId = await generateUniqueSessionId();
    const newSession = new BingoSession({
      sessionId,
      cardCode: cardCode.toUpperCase(),
      userId: req.auth ? req.auth.user.id : null
    });
    await newSession.save();
    console.log(`✅ Initialized new session: ${sessionId} for user: ${req.auth ? req.auth.user.id : 'Anonymous'}`);
    res.status(201).json({
      success: true,
      sessionId: newSession.sessionId,
      cardCode: newSession.cardCode,
      completedCells: newSession.completedCells,
      message: 'Session initialized successfully.'
    });

  } catch (error) {
    console.error('❌ Error initializing session:', error);
    if (error.message.includes('Unable to generate unique session ID')) {
        return res.status(500).json({ success: false, error: error.message });
    }
    res.status(500).json({
      success: false,
      error: 'Internal server error while initializing session',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});


// Generate and store a new bingo card
app.post('/api/generate-card', async (req, res) => {
  try {
    const { difficulty, pokemon } = req.body;

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

    const invalidPokemon = pokemon.find(p => !p.name || typeof p.name !== 'string');
    if (invalidPokemon) {
      return res.status(400).json({ 
        success: false,
        error: 'All pokemon must have a valid name.' 
      });
    }

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
      expiresAt: new Date(Date.now() + 2592000 * 1000)
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

// Get session data
app.get('/api/session/:sessionId', async (req, res) => {
  try {
    const { sessionId } = req.params;
    if (!sessionId) {
      return res.status(400).json({ success: false, error: 'sessionId parameter is required.' });
    }

    const session = await BingoSession.findOne({ sessionId });

    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found.' });
    }

    session.lastAccessed = new Date();
    await session.save();

    console.log(`📋 Retrieved session: ${sessionId}`);
    res.json({
      success: true,
      sessionId: session.sessionId,
      cardCode: session.cardCode,
      completedCells: session.completedCells,
      createdAt: session.createdAt,
      lastAccessed: session.lastAccessed
    });

  } catch (error) {
    console.error('❌ Error retrieving session:', error);
    res.status(500).json({
      success: false,
      error: 'Internal server error while retrieving session',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// GET a user's saved cards
app.get('/api/user/cards', authMiddleware, async (req, res) => {
    try {
        const userId = req.auth.user.id;
        const savedSessions = await BingoSession.find({ userId, isSaved: true })
            .sort({ lastAccessed: -1 }) // Show most recent first
            .select('sessionId sessionName cardCode lastAccessed createdAt') // Select only needed fields
            .lean(); // Use .lean() for faster read-only queries

        res.json({ success: true, cards: savedSessions });
    } catch (error) {
        console.error('❌ Error fetching user cards:', error);
        res.status(500).json({ success: false, error: 'Server error while fetching cards.' });
    }
});

// Update completed cells for a session
app.put('/api/session/:sessionId/update', async (req, res) => {
  try {
    const { sessionId } = req.params;
    const { completedCells } = req.body;

    if (!sessionId) {
      return res.status(400).json({ success: false, error: 'sessionId parameter is required.' });
    }

    if (!completedCells || !Array.isArray(completedCells) || completedCells.length !== 25 || !completedCells.every(c => typeof c === 'boolean')) {
      return res.status(400).json({ success: false, error: 'Invalid completedCells data. Expected an array of 25 booleans.' });
    }

    const session = await BingoSession.findOne({ sessionId });

    if (!session) {
      return res.status(404).json({ success: false, error: 'Session not found.' });
    }

    session.completedCells = completedCells;
    session.lastAccessed = new Date();
    await session.save();

    console.log(`🔄 Updated session: ${sessionId}`);
    res.json({
      success: true,
      message: 'Session updated successfully.',
      completedCells: session.completedCells
    });

  } catch (error) {
    console.error('❌ Error updating session:', error);
     if (error.name === 'ValidationError') {
        return res.status(400).json({
            success: false,
            error: 'Validation error for completedCells',
            details: Object.values(error.errors).map(e => e.message)
        });
    }
    res.status(500).json({
      success: false,
      error: 'Internal server error while updating session',
      details: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// SAVE a session with a name
app.put('/api/session/:sessionId/save', authMiddleware, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const { sessionName } = req.body;
        const userId = req.auth.user.id;

        if (!sessionName) {
            return res.status(400).json({ success: false, error: 'sessionName is required.' });
        }

        const session = await BingoSession.findOneAndUpdate(
            { sessionId, userId }, // Ensure user can only save their own session
            { isSaved: true, sessionName: sessionName, lastAccessed: new Date() },
            { new: true } // Return the updated document
        );

        if (!session) {
            return res.status(404).json({ success: false, error: 'Session not found or user unauthorized.' });
        }
        res.json({ success: true, message: 'Session saved successfully.', session });
    } catch (error) {
        console.error('❌ Error saving session:', error);
        res.status(500).json({ success: false, error: 'Server error while saving session.' });
    }
});

// RENAME a session
app.put('/api/session/:sessionId/rename', authMiddleware, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const { newName } = req.body;
        const userId = req.auth.user.id;

        if (!newName) {
            return res.status(400).json({ success: false, error: 'newName is required.' });
        }
        
        const session = await BingoSession.findOneAndUpdate(
            { sessionId, userId },
            { sessionName: newName },
            { new: true }
        );

        if (!session) {
            return res.status(404).json({ success: false, error: 'Session not found or user unauthorized.' });
        }
        res.json({ success: true, message: 'Session renamed successfully.', session });
    } catch (error) {
        // ... error handling
    }
});

// DELETE a session
app.delete('/api/session/:sessionId', authMiddleware, async (req, res) => {
    try {
        const { sessionId } = req.params;
        const userId = req.auth.user.id;

        const result = await BingoSession.deleteOne({ sessionId, userId });

        if (result.deletedCount === 0) {
            return res.status(404).json({ success: false, error: 'Session not found or user unauthorized.' });
        }
        res.json({ success: true, message: 'Session deleted successfully.' });
    } catch (error) {
        // ... error handling
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
