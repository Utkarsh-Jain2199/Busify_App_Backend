import mongoose, { Schema } from "mongoose";

const UserSchema = new Schema({
  google_id: { type: String },
  phone: { type: String },
  name: { type: String },
  email: { type: String, required: true, unique: true },
  password: { type: String },
  user_photo: { type: String },
  age: { type: Number, min: 1, max: 120 },
  gender: { type: String, enum: ['male', 'female', 'other'] },
  createdAt: { type: Date, default: Date.now },
  updatedAt: { type: Date, default: Date.now },
});

const User = mongoose.model("User", UserSchema);

export default User;
