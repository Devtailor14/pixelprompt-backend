import mongoose from 'mongoose';
import userModel from "../models/usermodel.js";
import bcrypt from 'bcrypt'
import jwt from 'jsonwebtoken'
import razorpay from 'razorpay'
import transactionModel from "../models/transactionModel.js";

// Validation helper functions
const validateEmail = (email) => {
    const emailRegex = /^[^\s@]+@[^\s@]+\.[^\s@]+$/;
    return emailRegex.test(email);
};

const validatePassword = (password) => {
    return password && password.length >= 8; // Increased minimum length
};

// Rate limiting helper (implement with express-rate-limit)
const rateLimitConfig = {
    windowMs: 15 * 60 * 1000, // 15 minutes
    max: 5 // limit each IP to 5 requests per windowMs
};

const registerUser = async (req, res) => {
    try {
        const { name, email, password } = req.body;

        // Input validation
        if (!name || !email || !password) {
            return res.status(400).json({ success: false, message: 'Missing required fields' });
        }

        if (!validateEmail(email)) {
            return res.status(400).json({ success: false, message: 'Invalid email format' });
        }

        if (!validatePassword(password)) {
            return res.status(400).json({ 
                success: false, 
                message: 'Password must be at least 8 characters long' 
            });
        }

        // Check if user already exists
        const existingUser = await userModel.findOne({ email: email.toLowerCase() });
        if (existingUser) {
            return res.status(409).json({ success: false, message: 'User already exists' });
        }

        // Hash password
        const salt = await bcrypt.genSalt(12); // Increased salt rounds
        const hashedPassword = await bcrypt.hash(password, salt);

        const userData = {
            name: name.trim(),
            email: email.toLowerCase(),
            password: hashedPassword,
            creditBalance: 5
        };

        const newUser = new userModel(userData);
        const user = await newUser.save();

        const token = jwt.sign(
            { id: user._id, email: user.email }, 
            process.env.JWT_SECRET, 
            { expiresIn: '7d' }
        );

        res.status(201).json({ 
            success: true, 
            token, 
            user: { 
                name: user.name, 
                email: user.email,
                id: user._id,
                creditBalance: user.creditBalance
            } 
        });

    } catch (error) {
        console.error('Registration error:', error);
        res.status(500).json({ success: false, message: 'Registration failed' });
    }
};

const loginUser = async (req, res) => {
    try {
        const { email, password } = req.body;

        if (!email || !password) {
            return res.status(400).json({ success: false, message: 'Email and password required' });
        }

        // Find user by email (case insensitive)
        const user = await userModel.findOne({ email: email.toLowerCase() });
        if (!user) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        // Check password
        const isMatch = await bcrypt.compare(password, user.password);
        if (!isMatch) {
            return res.status(401).json({ success: false, message: 'Invalid credentials' });
        }

        const token = jwt.sign(
            { id: user._id, email: user.email }, 
            process.env.JWT_SECRET, 
            { expiresIn: '7d' }
        );

        res.json({ 
            success: true, 
            token, 
            user: { 
                name: user.name, 
                email: user.email,
                id: user._id,
                creditBalance: user.creditBalance
            } 
        });

    } catch (error) {
        console.error('Login error:', error);
        res.status(500).json({ success: false, message: 'Login failed' });
    }
};

const userCredits = async (req, res) => {
    try {
        // Get token from headers
        const token = req.headers.token || req.headers.authorization?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }

        // Verify and decode token
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;

        const user = await userModel.findById(userId).select('-password');
        
        if (!user) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }
        
        res.json({ 
            success: true, 
            credits: user.creditBalance || 0,
            user: { 
                name: user.name, 
                email: user.email,
                id: user._id 
            } 
        });

    } catch (error) {
        console.error('userCredits error:', error);
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ success: false, message: 'Invalid token' });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ success: false, message: 'Token expired' });
        }
        
        res.status(500).json({ success: false, message: 'Failed to fetch user credits' });
    }
};

// Razorpay configuration
let razorpayInstance = null;

const getRazorpayInstance = () => {
    if (razorpayInstance) {
        return razorpayInstance;
    }
    
    const { RAZORPAY_KEY_ID, RAZORPAY_KEY_SECRET } = process.env;
    
    if (!RAZORPAY_KEY_ID || !RAZORPAY_KEY_SECRET) {
        console.warn('Razorpay credentials not configured');
        return null;
    }
    
    try {
        razorpayInstance = new razorpay({
            key_id: RAZORPAY_KEY_ID,
            key_secret: RAZORPAY_KEY_SECRET,
        });
        console.log('Razorpay initialized successfully');
        return razorpayInstance;
    } catch (error) {
        console.error('Failed to initialize Razorpay:', error.message);
        return null;
    }
};

// Plan configuration
const PLANS = {
    Basic: { credits: 100, amount: 10 },
    Advanced: { credits: 500, amount: 50 },
    Business: { credits: 5000, amount: 250 }
};

// Updated paymentRazorpay function
const paymentRazorpay = async (req, res) => {
    try {
        const razorpay = getRazorpayInstance();
        
        if (!razorpay) {
            return res.status(503).json({ 
                success: false, 
                message: 'Payment service not available' 
            });
        }

        const { userId, planId } = req.body;

        if (!userId || !planId) {
            return res.status(400).json({ success: false, message: 'Missing required fields' });
        }

        const userData = await userModel.findById(userId);
        if (!userData) {
            return res.status(404).json({ success: false, message: 'User not found' });
        }

        const plan = PLANS[planId];
        if (!plan) {
            return res.status(400).json({ success: false, message: 'Invalid plan selected' });
        }

        const shortReceipt = `rcpt_${planId}_${Date.now()}`.substring(0, 40);

        const options = {
            amount: plan.amount * 100,
            currency: 'INR',
            receipt: shortReceipt,
            notes: {
                userId: userId,
                plan: planId,
                credits: plan.credits
            }
        };

        const order = await razorpay.orders.create(options);

        const transactionData = {
            userId: new mongoose.Types.ObjectId(userId), // Convert to ObjectId
            plan: planId, 
            amount: plan.amount, 
            credits: plan.credits, 
            payment: false,
            date: new Date(), // Use Date object
            razorpayOrderId: order.id
        };

        // Save transaction to database
        const transaction = new transactionModel(transactionData);
        const savedTransaction = await transaction.save();

        console.log(`Transaction created: ${savedTransaction._id} for user ${userId}`);

        res.json({
            success: true,
            order: order,
            transactionData: savedTransaction
        });

    } catch (error) {
        console.error('Payment creation error:', error);
        res.status(500).json({ success: false, message: 'Failed to create payment order' });
    }
};

// Updated verifyRazorpay function
const verifyRazorpay = async (req, res) => {
    try {
        const { razorpay_order_id, razorpay_payment_id, razorpay_signature } = req.body;

        const token = req.headers.token || req.headers.authorization?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;

        const razorpay = getRazorpayInstance();
        if (!razorpay) {
            return res.status(503).json({ success: false, message: 'Payment service not available' });
        }

        // Verify payment signature
        const crypto = await import('crypto');
        const sign = razorpay_order_id + "|" + razorpay_payment_id;
        const expectedSign = crypto.default
            .createHmac("sha256", process.env.RAZORPAY_KEY_SECRET)
            .update(sign.toString())
            .digest("hex");

        if (razorpay_signature !== expectedSign) {
            return res.status(400).json({ success: false, message: "Invalid payment signature" });
        }

        // Get order details
        const order = await razorpay.orders.fetch(razorpay_order_id);
        const { plan } = order.notes;
        
        const planConfig = PLANS[plan];
        if (!planConfig) {
            return res.status(400).json({ success: false, message: 'Invalid plan' });
        }

        // Update user credits
        const user = await userModel.findById(userId);
        if (!user) {
            return res.status(404).json({ success: false, message: "User not found" });
        }

        user.creditBalance += planConfig.credits;
        await user.save();
        
        // Update transaction using razorpayOrderId
        const updatedTransaction = await transactionModel.findOneAndUpdate(
            { 
                razorpayOrderId: razorpay_order_id,
                payment: false
            },
            { 
                payment: true,
                razorpayPaymentId: razorpay_payment_id
            },
            { new: true }
        );
        
        console.log(`Payment verified: ${planConfig.credits} credits added to user ${userId}`);
        console.log('Updated transaction:', updatedTransaction);
        
        res.json({ 
            success: true, 
            message: "Payment verified and credits added successfully",
            creditBalance: user.creditBalance
        });

    } catch (error) {
        console.error('Payment verification error:', error);
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ success: false, message: 'Invalid token' });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ success: false, message: 'Token expired' });
        }
        
        res.status(500).json({ success: false, message: 'Payment verification failed' });
    }
};

// Updated getUserTransactions function
const getUserTransactions = async (req, res) => {
    try {
        const token = req.headers.token || req.headers.authorization?.replace('Bearer ', '');
        
        if (!token) {
            return res.status(401).json({ success: false, message: 'No token provided' });
        }

        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        const userId = decoded.id;

        const page = parseInt(req.query.page) || 1;
        const limit = parseInt(req.query.limit) || 10;
        const skip = (page - 1) * limit;

        const transactions = await transactionModel
            .find({ userId: new mongoose.Types.ObjectId(userId) }) // Convert to ObjectId
            .sort({ createdAt: -1 }) // Use createdAt instead of date
            .skip(skip)
            .limit(limit)
            .lean();

        // Format the transactions
        const formattedTransactions = transactions.map(transaction => ({
            ...transaction,
            formattedDate: new Date(transaction.createdAt).toLocaleString(),
            status: transaction.payment ? 'Completed' : 'Pending'
        }));

        const totalTransactions = await transactionModel.countDocuments({ 
            userId: new mongoose.Types.ObjectId(userId) 
        });
        const totalPages = Math.ceil(totalTransactions / limit);

        res.json({
            success: true,
            transactions: formattedTransactions,
            pagination: {
                currentPage: page,
                totalPages,
                totalTransactions,
                hasNext: page < totalPages,
                hasPrev: page > 1
            }
        });

    } catch (error) {
        console.error('Get transactions error:', error);
        
        if (error.name === 'JsonWebTokenError') {
            return res.status(401).json({ success: false, message: 'Invalid token' });
        }
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ success: false, message: 'Token expired' });
        }
        
        res.status(500).json({ success: false, message: 'Failed to fetch transactions' });
    }
};

// Middleware for authentication
const authenticateToken = (req, res, next) => {
    const token = req.headers.token || req.headers.authorization?.replace('Bearer ', '');
    
    if (!token) {
        return res.status(401).json({ success: false, message: 'Access token required' });
    }

    try {
        const decoded = jwt.verify(token, process.env.JWT_SECRET);
        req.user = decoded;
        next();
    } catch (error) {
        if (error.name === 'TokenExpiredError') {
            return res.status(401).json({ success: false, message: 'Token expired' });
        }
        return res.status(403).json({ success: false, message: 'Invalid token' });
    }
};

export { 
    registerUser, 
    loginUser, 
    userCredits, 
    paymentRazorpay, 
    verifyRazorpay,
    getUserTransactions,
    authenticateToken
};