// server.js
const express = require('express');
const mongoose = require('mongoose');
const cors = require('cors');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const dotenv = require('dotenv');
const Groq = require('groq-sdk');

dotenv.config();

// Initialize Groq AI
const groq = new Groq({
  apiKey: process.env.GROQ_API_KEY || 'gsk_your_groq_api_key_here'
});

const app = express();

// Middleware
const allowedOrigins = [
  'http://localhost:3000',
  'http://localhost:5173',
  'http://localhost:5174',
  'https://workflow-frontend-iota.vercel.app',
  process.env.FRONTEND_URL || 'https://workflow-frontend-iota.vercel.app'
];

app.use(cors({
  origin: function(origin, callback) {
    // Allow requests with no origin (mobile apps, Postman, etc.)
    if (!origin) return callback(null, true);
    
    if (allowedOrigins.indexOf(origin) !== -1 || origin.includes('vercel.app') || origin.includes('netlify.app')) {
      callback(null, true);
    } else {
      callback(new Error('Not allowed by CORS'));
    }
  },
  credentials: true
}));
app.use(express.json());

// MongoDB connection
mongoose.connect(process.env.MONGODB_URI || 'mongodb://localhost:27017/workflow-auth', {
  useNewUrlParser: true,
  useUnifiedTopology: true,
})
.then(() => console.log('Connected to MongoDB'))
.catch(err => console.error('MongoDB connection error:', err));

// User Schema
const userSchema = new mongoose.Schema({
  email: {
    type: String,
    required: true,
    unique: true,
    lowercase: true,
    trim: true,
    match: [/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/, 'Please enter a valid email']
  },
  password: {
    type: String,
    required: true,
    minlength: 6
  },
  role: {
    type: String,
    enum: ['user', 'admin'],
    default: 'user'
  },
  name: {
    type: String,
    default: ''
  },
  onboardingCompleted: {
    type: Boolean,
    default: false
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  lastLogin: {
    type: Date,
    default: Date.now
  },
  isActive: {
    type: Boolean,
    default: true
  }
});

// Hash password before saving
userSchema.pre('save', async function(next) {
  if (!this.isModified('password')) return next();
  
  try {
    const salt = await bcrypt.genSalt(10);
    this.password = await bcrypt.hash(this.password, salt);
    next();
  } catch (error) {
    next(error);
  }
});

// Compare password method
userSchema.methods.comparePassword = async function(candidatePassword) {
  return await bcrypt.compare(candidatePassword, this.password);
};

const User = mongoose.model('User', userSchema);

// Onboarding Schema
const onboardingSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true,
    unique: true
  },
  businessName: {
    type: String,
    required: true,
    trim: true
  },
  userName: {
    type: String,
    required: true,
    trim: true
  },
  businessDescription: {
    type: String,
    required: true
  },
  idealCustomer: {
    type: String,
    required: true
  },
  leadSources: [{
    type: String,
    required: true
  }],
  leadSourcesOther: {
    type: String,
    default: ''
  },
  dealSize: {
    type: String,
    required: true
  },
  communicationPlatforms: [{
    type: String,
    required: true
  }],
  communicationOther: {
    type: String,
    default: ''
  },
  leadHandling: {
    type: String,
    required: true
  },
  salesGoal: {
    type: String,
    required: true
  },
  customerQuestions: [{
    type: String
  }],
  websiteLinks: {
    type: String,
    default: ''
  },
  urgency: {
    type: String,
    required: true
  },
  completedAt: {
    type: Date,
    default: Date.now
  }
});

const Onboarding = mongoose.model('Onboarding', onboardingSchema);

// Campaign Schema
const campaignSchema = new mongoose.Schema({
  userId: {
    type: mongoose.Schema.Types.ObjectId,
    ref: 'User',
    required: true
  },
  name: {
    type: String,
    required: true,
    trim: true
  },
  productName: {
    type: String,
    required: true,
    trim: true
  },
  productDescription: {
    type: String,
    required: true
  },
  price: {
    type: String,
    required: true
  },
  targetAudience: {
    type: String,
    required: true
  },
  platform: {
    type: String,
    enum: ['facebook', 'whatsapp', 'instagram', 'all'],
    default: 'all'
  },
  status: {
    type: String,
    enum: ['active', 'paused', 'completed'],
    default: 'active'
  },
  goal: {
    type: String,
    default: ''
  },
  stats: {
    leads: { type: Number, default: 0 },
    conversions: { type: Number, default: 0 },
    revenue: { type: Number, default: 0 },
    conversations: { type: Number, default: 0 }
  },
  createdAt: {
    type: Date,
    default: Date.now
  },
  updatedAt: {
    type: Date,
    default: Date.now
  }
});

const Campaign = mongoose.model('Campaign', campaignSchema);

// Generate JWT token
const generateToken = (userId) => {
  return jwt.sign(
    { userId },
    process.env.JWT_SECRET || 'your-secret-key',
    { expiresIn: '7d' }
  );
};

// Verify token middleware (supports bypass via env)
const authMiddleware = async (req, res, next) => {
  try {
    const BYPASS_AUTH = String(process.env.BYPASS_AUTH || '').toLowerCase() === 'true';
    if (BYPASS_AUTH) {
      // When bypassing, trust provided userId or fall back to a dev id
      const userId = req.body?.userId || req.header('x-user-id') || 'dev-user-id';
      req.user = { _id: userId, email: 'dev@example.com', role: 'admin', onboardingCompleted: false };
      return next();
    }

    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      throw new Error();
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user) {
      throw new Error();
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(401).json({ message: 'Please authenticate' });
  }
};

// Admin middleware (supports bypass via env)
const adminMiddleware = async (req, res, next) => {
  try {
    const BYPASS_AUTH = String(process.env.BYPASS_AUTH || '').toLowerCase() === 'true';
    if (BYPASS_AUTH) {
      const userId = req.body?.userId || req.header('x-user-id') || 'dev-admin-id';
      req.user = { _id: userId, email: 'admin@example.com', role: 'admin', onboardingCompleted: true };
      return next();
    }

    // First check if user is authenticated
    const token = req.header('Authorization')?.replace('Bearer ', '');
    
    if (!token) {
      throw new Error();
    }

    const decoded = jwt.verify(token, process.env.JWT_SECRET || 'your-secret-key');
    const user = await User.findById(decoded.userId).select('-password');
    
    if (!user || user.role !== 'admin') {
      throw new Error();
    }

    req.user = user;
    next();
  } catch (error) {
    res.status(403).json({ message: 'Access denied. Admin privileges required.' });
  }
};

// Validation middleware
const validateAuthInput = (req, res, next) => {
  const { email, password } = req.body;
  const errors = {};

  // Email validation
  if (!email) {
    errors.email = 'Email is required';
  } else if (!/^\w+([.-]?\w+)*@\w+([.-]?\w+)*(\.\w{2,3})+$/.test(email)) {
    errors.email = 'Please enter a valid email';
  }

  // Password validation
  if (!password) {
    errors.password = 'Password is required';
  } else if (password.length < 6) {
    errors.password = 'Password must be at least 6 characters';
  }

  if (Object.keys(errors).length > 0) {
    return res.status(400).json({ errors });
  }

  next();
};

// Test route
app.get('/', (req, res) => {
  res.json({ message: 'Auth server is running!' });
});

// Health check endpoint
app.get('/api/health', (req, res) => {
  res.json({ 
    status: 'ok',
    message: 'Backend is healthy',
    timestamp: new Date().toISOString()
  });
});

// AUTH ROUTES

// Sign Up Route
app.post('/api/auth/signup', validateAuthInput, async (req, res) => {
  try {
    const { email, password } = req.body;

    // Check if user already exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({
        errors: { email: 'An account with this email already exists' }
      });
    }

    // Create new user
    const user = new User({ email, password });
    await user.save();

    // Generate token
    const token = generateToken(user._id);

    res.status(201).json({
      success: true,
      message: 'Account created successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        onboardingCompleted: user.onboardingCompleted
      }
    });
  } catch (error) {
    console.error('Signup error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Sign In Route
app.post('/api/auth/signin', validateAuthInput, async (req, res) => {
  try {
    const { email, password } = req.body;

    const user = await User.findOne({ email });
    if (!user) {
      return res.status(401).json({
        errors: { email: 'Invalid email or password' }
      });
    }

    const isMatch = await user.comparePassword(password);
    if (!isMatch) {
      return res.status(401).json({
        errors: { password: 'Invalid email or password' }
      });
    }

    // Generate token
    const token = generateToken(user._id);

    res.json({
      success: true,
      message: 'Signed in successfully',
      token,
      user: {
        id: user._id,
        email: user.email,
        role: user.role,
        onboardingCompleted: user.onboardingCompleted
      }
    });
  } catch (error) {
    console.error('Signin error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// Get current user route (protected)
app.get('/api/auth/me', authMiddleware, async (req, res) => {
  res.json({
    success: true,
    user: {
      id: req.user._id,
      email: req.user.email,
      role: req.user.role,
      onboardingCompleted: req.user.onboardingCompleted
    }
  });
});

// ONBOARDING ROUTES

// Submit Onboarding Data
app.post('/api/onboarding', authMiddleware, async (req, res) => {
  try {
    const { userId, ...onboardingData } = req.body;

    // Verify that the authenticated user matches the userId
    if (req.user._id.toString() !== userId) {
      return res.status(403).json({
        success: false,
        message: 'Access denied. You can only submit your own onboarding data.'
      });
    }

    // Check if user has already completed onboarding
    const existingOnboarding = await Onboarding.findOne({ userId });
    if (existingOnboarding) {
      return res.status(400).json({
        success: false,
        message: 'Onboarding has already been completed for this user.'
      });
    }

    // Validate required fields
    const requiredFields = [
      'businessName', 'userName', 'businessDescription', 'idealCustomer',
      'leadSources', 'dealSize', 'communicationPlatforms', 'leadHandling',
      'salesGoal', 'urgency'
    ];

    const missingFields = requiredFields.filter(field => {
      const value = onboardingData[field];
      if (Array.isArray(value)) {
        return value.length === 0;
      }
      return !value || (typeof value === 'string' && value.trim() === '');
    });

    if (missingFields.length > 0) {
      return res.status(400).json({
        success: false,
        message: `Missing required fields: ${missingFields.join(', ')}`
      });
    }

    // Create onboarding record
    const onboarding = new Onboarding({
      userId,
      ...onboardingData
    });

    await onboarding.save();

    // Update user's onboarding status
    await User.findByIdAndUpdate(userId, { 
      onboardingCompleted: true,
      name: onboardingData.userName // Update user's name from onboarding
    });

    res.status(201).json({
      success: true,
      message: 'Onboarding completed successfully',
      onboarding: {
        id: onboarding._id,
        completedAt: onboarding.completedAt
      }
    });

  } catch (error) {
    console.error('Onboarding error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.',
      error: process.env.NODE_ENV === 'development' ? error.message : undefined
    });
  }
});

// Get onboarding data (protected route)
app.get('/api/onboarding/:userId', authMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;

    // Verify that the authenticated user matches the userId or is admin
    if (req.user._id.toString() !== userId && req.user.role !== 'admin') {
      return res.status(403).json({
        success: false,
        message: 'Access denied.'
      });
    }

    const onboarding = await Onboarding.findOne({ userId }).populate('userId', 'email name');

    if (!onboarding) {
      return res.status(404).json({
        success: false,
        message: 'Onboarding data not found'
      });
    }

    res.json({
      success: true,
      onboarding
    });

  } catch (error) {
    console.error('Get onboarding error:', error);
    res.status(500).json({
      success: false,
      message: 'Server error. Please try again later.'
    });
  }
});

// ADMIN ROUTES

// Get all users (admin only)
app.get('/api/admin/users', adminMiddleware, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '', role = '' } = req.query;
    
    const query = {};
    if (search) {
      query.$or = [
        { email: { $regex: search, $options: 'i' } },
        { name: { $regex: search, $options: 'i' } }
      ];
    }
    if (role) {
      query.role = role;
    }

    const totalUsers = await User.countDocuments(query);
    const users = await User.find(query)
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    res.json({
      success: true,
      users,
      totalUsers,
      totalPages: Math.ceil(totalUsers / limit),
      currentPage: page
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching users', error: error.message });
  }
});

// Get dashboard statistics (admin only)
app.get('/api/admin/stats', adminMiddleware, async (req, res) => {
  try {
    const totalUsers = await User.countDocuments();
    const totalAdmins = await User.countDocuments({ role: 'admin' });
    const activeUsers = await User.countDocuments({ isActive: true });
    const completedOnboarding = await User.countDocuments({ onboardingCompleted: true });
    
    // Get users registered in last 7 days
    const sevenDaysAgo = new Date();
    sevenDaysAgo.setDate(sevenDaysAgo.getDate() - 7);
    const recentUsers = await User.countDocuments({
      createdAt: { $gte: sevenDaysAgo }
    });

    // Get recent onboarding completions
    const recentOnboarding = await Onboarding.countDocuments({
      completedAt: { $gte: sevenDaysAgo }
    });

    // Get recent user list
    const recentUsersList = await User.find()
      .select('-password')
      .sort({ createdAt: -1 })
      .limit(5);

    res.json({
      success: true,
      stats: {
        totalUsers,
        totalAdmins,
        activeUsers,
        recentUsers,
        completedOnboarding,
        recentOnboarding
      },
      recentUsersList
    });
  } catch (error) {
    res.status(500).json({ message: 'Error fetching stats', error: error.message });
  }
});

// Get all onboarding data (admin only)
app.get('/api/admin/onboarding', adminMiddleware, async (req, res) => {
  try {
    const { page = 1, limit = 10, search = '' } = req.query;
    
    let query = {};
    if (search) {
      // Find users matching search criteria first
      const users = await User.find({
        $or: [
          { email: { $regex: search, $options: 'i' } },
          { name: { $regex: search, $options: 'i' } }
        ]
      }).select('_id');
      
      const userIds = users.map(user => user._id);
      query = { userId: { $in: userIds } };
    }

    const totalOnboarding = await Onboarding.countDocuments(query);
    const onboardingData = await Onboarding.find(query)
      .populate('userId', 'email name createdAt')
      .sort({ completedAt: -1 })
      .limit(limit * 1)
      .skip((page - 1) * limit);

    res.json({
      success: true,
      onboardingData,
      totalOnboarding,
      totalPages: Math.ceil(totalOnboarding / limit),
      currentPage: page
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching onboarding data', 
      error: error.message 
    });
  }
});

// Update user (admin only)
app.put('/api/admin/users/:userId', adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;
    const { email, name, role, isActive } = req.body;

    // Prevent admin from changing their own role
    if (userId === req.user._id.toString() && role !== req.user.role) {
      return res.status(400).json({ message: 'You cannot change your own role' });
    }

    const updateData = {};
    if (email) updateData.email = email;
    if (name !== undefined) updateData.name = name;
    if (role) updateData.role = role;
    if (isActive !== undefined) updateData.isActive = isActive;

    const updatedUser = await User.findByIdAndUpdate(
      userId,
      updateData,
      { new: true, runValidators: true }
    ).select('-password');

    if (!updatedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    res.json({
      success: true,
      message: 'User updated successfully',
      user: updatedUser
    });
  } catch (error) {
    res.status(500).json({ message: 'Error updating user', error: error.message });
  }
});

// Delete user (admin only)
app.delete('/api/admin/users/:userId', adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;

    // Prevent admin from deleting themselves
    if (userId === req.user._id.toString()) {
      return res.status(400).json({ message: 'You cannot delete your own account' });
    }

    const deletedUser = await User.findByIdAndDelete(userId);
    
    if (!deletedUser) {
      return res.status(404).json({ message: 'User not found' });
    }

    // Also delete associated onboarding data
    await Onboarding.findOneAndDelete({ userId });

    res.json({
      success: true,
      message: 'User deleted successfully'
    });
  } catch (error) {
    res.status(500).json({ message: 'Error deleting user', error: error.message });
  }
});

// Create new user (admin only)
app.post('/api/admin/users', adminMiddleware, async (req, res) => {
  try {
    const { email, password, name, role = 'user' } = req.body;

    // Validate input
    if (!email || !password) {
      return res.status(400).json({ 
        message: 'Email and password are required' 
      });
    }

    if (password.length < 6) {
      return res.status(400).json({ 
        message: 'Password must be at least 6 characters' 
      });
    }

    // Check if user exists
    const existingUser = await User.findOne({ email });
    if (existingUser) {
      return res.status(400).json({ 
        message: 'User with this email already exists' 
      });
    }

    // Create new user
    const user = new User({
      email,
      password,
      name,
      role
    });

    await user.save();

    res.status(201).json({
      success: true,
      message: 'User created successfully',
      user: {
        id: user._id,
        email: user.email,
        name: user.name,
        role: user.role
      }
    });
  } catch (error) {
    res.status(500).json({ message: 'Error creating user', error: error.message });
  }
});

// Reset user password (admin only)
app.post('/api/admin/users/:userId/reset-password', adminMiddleware, async (req, res) => {
  try {
    const { userId } = req.params;
    const { newPassword } = req.body;

    if (!newPassword || newPassword.length < 6) {
      return res.status(400).json({ 
        message: 'Password must be at least 6 characters' 
      });
    }

    const user = await User.findById(userId);
    if (!user) {
      return res.status(404).json({ message: 'User not found' });
    }

    user.password = newPassword;
    await user.save();

    res.json({
      success: true,
      message: 'Password reset successfully'
    });
  } catch (error) {
    res.status(500).json({ message: 'Error resetting password', error: error.message });
  }
});

// CAMPAIGN ROUTES

// Create campaign
app.post('/api/campaigns', authMiddleware, async (req, res) => {
  try {
    const { name, productName, productDescription, price, targetAudience, platform, goal } = req.body;
    
    const campaign = new Campaign({
      userId: req.user._id,
      name,
      productName,
      productDescription,
      price,
      targetAudience,
      platform: platform || 'all',
      goal: goal || ''
    });
    
    await campaign.save();
    
    res.status(201).json({
      success: true,
      message: 'Campaign created successfully',
      campaign
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error creating campaign', 
      error: error.message 
    });
  }
});

// Get all campaigns for user
app.get('/api/campaigns', authMiddleware, async (req, res) => {
  try {
    const campaigns = await Campaign.find({ userId: req.user._id })
      .sort({ createdAt: -1 });
    
    res.json({
      success: true,
      campaigns
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching campaigns', 
      error: error.message 
    });
  }
});

// Get single campaign
app.get('/api/campaigns/:id', authMiddleware, async (req, res) => {
  try {
    const campaign = await Campaign.findOne({ 
      _id: req.params.id, 
      userId: req.user._id 
    });
    
    if (!campaign) {
      return res.status(404).json({ 
        success: false, 
        message: 'Campaign not found' 
      });
    }
    
    res.json({
      success: true,
      campaign
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error fetching campaign', 
      error: error.message 
    });
  }
});

// Update campaign
app.put('/api/campaigns/:id', authMiddleware, async (req, res) => {
  try {
    const { name, productName, productDescription, price, targetAudience, platform, status, goal } = req.body;
    
    const campaign = await Campaign.findOneAndUpdate(
      { _id: req.params.id, userId: req.user._id },
      { 
        name, 
        productName, 
        productDescription, 
        price, 
        targetAudience, 
        platform, 
        status,
        goal,
        updatedAt: Date.now()
      },
      { new: true, runValidators: true }
    );
    
    if (!campaign) {
      return res.status(404).json({ 
        success: false, 
        message: 'Campaign not found' 
      });
    }
    
    res.json({
      success: true,
      message: 'Campaign updated successfully',
      campaign
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error updating campaign', 
      error: error.message 
    });
  }
});

// Delete campaign
app.delete('/api/campaigns/:id', authMiddleware, async (req, res) => {
  try {
    const campaign = await Campaign.findOneAndDelete({ 
      _id: req.params.id, 
      userId: req.user._id 
    });
    
    if (!campaign) {
      return res.status(404).json({ 
        success: false, 
        message: 'Campaign not found' 
      });
    }
    
    res.json({
      success: true,
      message: 'Campaign deleted successfully'
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error deleting campaign', 
      error: error.message 
    });
  }
});

// Update campaign stats (for tracking leads, conversions, revenue)
app.patch('/api/campaigns/:id/stats', authMiddleware, async (req, res) => {
  try {
    const { leads, conversions, revenue, conversations } = req.body;
    
    const campaign = await Campaign.findOne({ 
      _id: req.params.id, 
      userId: req.user._id 
    });
    
    if (!campaign) {
      return res.status(404).json({ 
        success: false, 
        message: 'Campaign not found' 
      });
    }
    
    if (leads !== undefined) campaign.stats.leads = leads;
    if (conversions !== undefined) campaign.stats.conversions = conversions;
    if (revenue !== undefined) campaign.stats.revenue = revenue;
    if (conversations !== undefined) campaign.stats.conversations = conversations;
    
    campaign.updatedAt = Date.now();
    await campaign.save();
    
    res.json({
      success: true,
      message: 'Campaign stats updated',
      campaign
    });
  } catch (error) {
    res.status(500).json({ 
      success: false, 
      message: 'Error updating stats', 
      error: error.message 
    });
  }
});

// FACEBOOK MESSENGER WEBHOOK

// Webhook verification (Facebook will call this to verify your webhook)
app.get('/webhook', (req, res) => {
  const VERIFY_TOKEN = process.env.FB_VERIFY_TOKEN || 'workflow_verify_token_2024';
  
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  
  if (mode && token) {
    if (mode === 'subscribe' && token === VERIFY_TOKEN) {
      console.log('✅ Webhook verified!');
      res.status(200).send(challenge);
    } else {
      console.log('❌ Webhook verification failed!');
      res.sendStatus(403);
    }
  }
});

// Webhook endpoint to receive messages
app.post('/webhook', async (req, res) => {
  const body = req.body;
  
  // Check if this is a page subscription
  if (body.object === 'page') {
    // Iterate over each entry (there may be multiple if batched)
    body.entry.forEach(async (entry) => {
      // Get the webhook event
      const webhookEvent = entry.messaging[0];
      console.log('📨 Received webhook event:', JSON.stringify(webhookEvent, null, 2));
      
      // Get sender PSID
      const senderPsid = webhookEvent.sender.id;
      
      // Check if the event is a message or postback
      if (webhookEvent.message) {
        await handleMessage(senderPsid, webhookEvent.message);
      } else if (webhookEvent.postback) {
        await handlePostback(senderPsid, webhookEvent.postback);
      }
    });
    
    // Return 200 OK to acknowledge receipt
    res.status(200).send('EVENT_RECEIVED');
  } else {
    res.sendStatus(404);
  }
});

// Store conversation history (in-memory for now, should be in DB for production)
const conversationHistory = new Map();

// Handle incoming messages with Groq AI
async function handleMessage(senderPsid, receivedMessage) {
  let response;
  
  // Check if the message contains text
  if (receivedMessage.text) {
    const messageText = receivedMessage.text;
    
    console.log(`💬 Message from ${senderPsid}: ${messageText}`);
    
    try {
      // Get or initialize conversation history for this user
      if (!conversationHistory.has(senderPsid)) {
        conversationHistory.set(senderPsid, []);
      }
      const history = conversationHistory.get(senderPsid);
      
      // Add user message to history
      history.push({
        role: 'user',
        content: messageText
      });
      
      // Keep only last 10 messages to avoid token limits
      if (history.length > 10) {
        history.shift();
      }
      
      // Generate AI response using Groq
      const aiResponse = await generateGroqResponse(messageText, history);
      
      // Add AI response to history
      history.push({
        role: 'assistant',
        content: aiResponse
      });
      
      response = {
        text: aiResponse
      };
      
      console.log(`🤖 Leo AI: ${aiResponse}`);
      
    } catch (error) {
      console.error('❌ Groq AI error:', error);
      // Fallback response if AI fails
      response = {
        text: `Hey! 👋 I'm Leo, your AI sales assistant. I'm here to help! What can I do for you today?`
      };
    }
    
  } else if (receivedMessage.attachments) {
    // Handle attachments (images, videos, etc.)
    response = {
      text: `Thanks for sharing! 📎 I can see you sent me something. How can I help you today?`
    };
  }
  
  // Send the response message
  await callSendAPI(senderPsid, response);
}

// Generate intelligent response using Groq AI with campaign knowledge
async function generateGroqResponse(userMessage, conversationHistory) {
  try {
    // Fetch active campaigns to give AI context
    const activeCampaigns = await Campaign.find({ status: 'active' })
      .limit(5)
      .sort({ createdAt: -1 })
      .lean();
    
    // Build campaign knowledge for AI
    let campaignKnowledge = '';
    if (activeCampaigns.length > 0) {
      campaignKnowledge = '\n\n**ACTIVE CAMPAIGNS (Use this to answer customer questions):**\n';
      activeCampaigns.forEach((campaign, index) => {
        campaignKnowledge += `
${index + 1}. **${campaign.productName}** (${campaign.name})
   - Description: ${campaign.productDescription}
   - Price: ${campaign.price}
   - Target Audience: ${campaign.targetAudience}
   - Platform: ${campaign.platform}
   - Goal: ${campaign.goal || 'Generate leads and sales'}
   - Stats: ${campaign.stats.leads} leads, ${campaign.stats.conversions} conversions, ₹${campaign.stats.revenue} revenue
`;
      });
      campaignKnowledge += '\n**When customers ask about products, pricing, or what you offer, use the campaign information above to give specific, accurate answers.**\n';
    } else {
      campaignKnowledge = '\n\n**Note:** No active campaigns yet. Focus on WorkFlow platform features and benefits.\n';
    }

    const systemPrompt = `You are Leo, an expert AI sales assistant. Your role is to:

1. **Be Friendly & Professional**: Greet warmly, be conversational, use emojis appropriately
2. **Understand Intent**: Identify if the customer wants to know about products, pricing, features, or make a purchase
3. **Provide Value**: Give helpful, specific information using the campaign data below
4. **Guide to Action**: Gently guide customers toward making a purchase
5. **Handle Objections**: Address concerns professionally and provide solutions
6. **Be Concise**: Keep responses under 3-4 sentences unless detailed explanation is needed

**About WorkFlow:**
- AI-powered sales automation platform
- Automates customer conversations on Facebook Messenger, WhatsApp, Instagram
- Features: Campaign management, lead tracking, AI responses, analytics, CRM
- Perfect for: Small businesses, agencies, e-commerce, service providers
${campaignKnowledge}
**Your Personality:**
- Enthusiastic but not pushy
- Helpful and solution-oriented
- Professional yet friendly
- Use emojis naturally (1-2 per message)

**IMPORTANT:** When customers ask about products, prices, or what you're selling, refer to the ACTIVE CAMPAIGNS above and give specific details about those products. Don't make up information - use only what's in the campaigns.

Keep responses natural, conversational, and focused on helping the customer.`;

    const completion = await groq.chat.completions.create({
      messages: [
        { role: 'system', content: systemPrompt },
        ...conversationHistory
      ],
      model: 'llama-3.1-70b-versatile', // Fast and intelligent model
      temperature: 0.7,
      max_tokens: 400,
      top_p: 1,
    });

    return completion.choices[0]?.message?.content || "I'm here to help! What would you like to know?";
    
  } catch (error) {
    console.error('Groq API error:', error);
    throw error;
  }
}

// Handle postbacks (button clicks)
async function handlePostback(senderPsid, receivedPostback) {
  let response;
  
  const payload = receivedPostback.payload;
  
  console.log(`🔘 Postback from ${senderPsid}: ${payload}`);
  
  if (payload === 'GET_STARTED') {
    response = {
      text: `Welcome! 🎉 I'm Leo, your AI sales assistant. I'm here to help you find the perfect product. What are you looking for today?`
    };
  } else if (payload === 'VIEW_PRODUCTS') {
    response = {
      text: `Here are our featured products! Let me know which one interests you and I'll give you all the details! 🛍️`
    };
  } else {
    response = {
      text: `Thanks for that! How else can I help you?`
    };
  }
  
  await callSendAPI(senderPsid, response);
}

// Send message to Facebook Messenger
async function callSendAPI(senderPsid, response) {
  const PAGE_ACCESS_TOKEN = process.env.FB_PAGE_ACCESS_TOKEN;
  
  if (!PAGE_ACCESS_TOKEN) {
    console.error('❌ No PAGE_ACCESS_TOKEN found! Cannot send message.');
    return;
  }
  
  const requestBody = {
    recipient: {
      id: senderPsid
    },
    message: response
  };
  
  try {
    const res = await fetch(`https://graph.facebook.com/v18.0/me/messages?access_token=${PAGE_ACCESS_TOKEN}`, {
      method: 'POST',
      headers: {
        'Content-Type': 'application/json'
      },
      body: JSON.stringify(requestBody)
    });
    
    const data = await res.json();
    
    if (data.error) {
      console.error('❌ Error sending message:', data.error);
    } else {
      console.log('✅ Message sent successfully!');
    }
  } catch (error) {
    console.error('❌ Error calling Send API:', error);
  }
}

// FACEBOOK OAUTH ROUTES

// Initiate Facebook OAuth
app.get('/auth/facebook', (req, res) => {
  const FB_APP_ID = process.env.FB_APP_ID || '1256408305896903';
  const REDIRECT_URI = `${req.protocol}://${req.get('host')}/auth/facebook/callback`;
  
  const permissions = [
    'pages_show_list',
    'pages_messaging',
    'pages_manage_metadata',
    'pages_read_engagement'
  ].join(',');

  const fbAuthUrl = `https://www.facebook.com/v18.0/dialog/oauth?client_id=${FB_APP_ID}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}&scope=${permissions}&response_type=code`;
  
  res.redirect(fbAuthUrl);
});

// Facebook OAuth callback
app.get('/auth/facebook/callback', async (req, res) => {
  const { code } = req.query;
  const FRONTEND_URL = process.env.FRONTEND_URL || 'https://workflow-frontend-iota.vercel.app';
  
  if (!code) {
    return res.redirect(`${FRONTEND_URL}/dashboard/integration?error=no_code`);
  }

  try {
    const FB_APP_ID = process.env.FB_APP_ID || '1256408305896903';
    const FB_APP_SECRET = process.env.FB_APP_SECRET || 'fc7fbca3fbecd5bc6b06331bc4da17c9';
    const REDIRECT_URI = `${req.protocol}://${req.get('host')}/auth/facebook/callback`;

    // Exchange code for access token
    const tokenUrl = `https://graph.facebook.com/v18.0/oauth/access_token?client_id=${FB_APP_ID}&client_secret=${FB_APP_SECRET}&code=${code}&redirect_uri=${encodeURIComponent(REDIRECT_URI)}`;
    
    const tokenResponse = await fetch(tokenUrl);
    const tokenData = await tokenResponse.json();

    if (!tokenData.access_token) {
      throw new Error('Failed to get access token');
    }

    // Get user's pages
    const pagesUrl = `https://graph.facebook.com/v18.0/me/accounts?access_token=${tokenData.access_token}`;
    const pagesResponse = await fetch(pagesUrl);
    const pagesData = await pagesResponse.json();

    if (pagesData.data && pagesData.data.length > 0) {
      // For simplicity, use the first page
      const page = pagesData.data[0];
      
      console.log('✅ Facebook Page connected:', page.name);
      
      // Redirect back to dashboard with success
      res.redirect(`${FRONTEND_URL}/dashboard/integration?fb_connected=true&page_name=${encodeURIComponent(page.name)}&page_id=${page.id}`);
    } else {
      res.redirect(`${FRONTEND_URL}/dashboard/integration?error=no_pages`);
    }
  } catch (error) {
    console.error('Facebook OAuth error:', error);
    res.redirect(`${FRONTEND_URL}/dashboard/integration?error=oauth_failed`);
  }
});

// Get Facebook app info
app.get('/api/facebook/app', (req, res) => {
  const FB_APP_ID = process.env.FB_APP_ID || '1256408305896903';
  res.json({
    appId: FB_APP_ID,
    appName: 'WorkFlow Sales Automation',
    callback: `${req.protocol}://${req.get('host')}/auth/facebook/callback`
  });
});

// Get integration status
app.get('/api/integrations/status', (req, res) => {
  // This would normally check database for connected integrations
  res.json({
    facebook: { connected: false },
    whatsapp: { connected: false },
    instagram: { connected: false }
  });
});

// Error handling middleware
app.use((err, req, res, next) => {
  console.error(err.stack);
  res.status(500).json({
    success: false,
    message: 'Something went wrong!'
  });
});

const PORT = process.env.PORT || 5000;
app.listen(PORT, () => {
  console.log(`Server running on port ${PORT}`);
  console.log(`Facebook OAuth callback: http://localhost:${PORT}/auth/facebook/callback`);
});
