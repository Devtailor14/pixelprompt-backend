import mongoose from "mongoose";

const transactionSchema = new mongoose.Schema({
    userId: { 
        type: mongoose.Schema.Types.ObjectId, // Changed from String to ObjectId
        ref: 'User', // Reference to User model
        required: true 
    },
    plan: { 
        type: String, 
        required: true,
        enum: ['Basic', 'Advanced', 'Business'] // Add validation
    },
    amount: { 
        type: Number, 
        required: true 
    },
    credits: { 
        type: Number, 
        required: true 
    },
    payment: { 
        type: Boolean, 
        default: false 
    },
    date: { 
        type: Date, // Changed from Number to Date
        default: Date.now // Add default value
    },
    razorpayOrderId: {
        type: String // Add this field to store Razorpay order ID
    },
    razorpayPaymentId: {
        type: String // Add this field to store payment ID after verification
    }
}, {
    timestamps: true // This will add createdAt and updatedAt fields automatically
});

// Use consistent naming - capital 'T' for Transaction
const transactionModel = mongoose.models.Transaction || mongoose.model("Transaction", transactionSchema);

export default transactionModel;