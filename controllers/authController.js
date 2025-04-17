import { userModel } from "../models/userModel.js";
import bcrypt from "bcryptjs";
import jwt from "jsonwebtoken";

export const register = async (req, res) => {
  const { name, email, password } = req.body;

  if (!name || !email || !password) {
    return res.json({ success: false, message: "Details Missing" });
  }

  try {
    // checking is the user exist already in the database
    const userExisting = await userModel.findOne({ email });
    if (userExisting) {
      return res.json({ success: false, message: "user already exist" });
    }
    // hashing the password
    const hashedPassword = await bcrypt.hash(password, 10);

    //saving the user to database
    const user = new userModel({ name, email, password: hashedPassword });
    await user.save();
    res.status(201).send({
      success: true,
      message: "User Register Successfully",
      user,
    });
    
    const token = jwt.sign({ id: user._id }, process.env.JWT_SECRECT, {
      expiresIn: "1d",
    });

    res.cookie("token", token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === "production",
      sameSite: process.env.NODE_ENV === "production" ? "none" : "strict",
      maxAge: 24 * 60 * 60 * 1000,
    });
  } catch (error) {
    res.json({ success: false, message: error.message });
  }
};
