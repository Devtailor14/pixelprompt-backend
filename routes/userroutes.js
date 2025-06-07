import express from 'express'
import {registerUser, loginUser, userCredits, paymentRazorpay, verifyRazorpay} from '../controllers/userController.js'
import userAuth from '../middlewares/auth.js'

const userRouter = express.Router()

userRouter.post('/register', registerUser)
userRouter.post('/login', loginUser)
userRouter.get('/credits', userCredits )
userRouter.post('/pay-razor', userAuth, paymentRazorpay) // Fixed: Added 'post'
userRouter.post('/verify-razor', userAuth, verifyRazorpay) // Added verify route

export default userRouter

// http://localhost:4000/api/user/register
// http://localhost:4000/api/user/login