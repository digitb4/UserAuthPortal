import mongoose, { Schema, Document } from 'mongoose';

export interface IUser extends Document {
    email: string;
    password: string;
    role: 'user' | 'admin' | 'moderator';
    sessionToken: string | null;
    resetToken: string | null;
    resetTokenExpiry: Date | null;
    mfaSecret: string | null;
    mfaEnabled: boolean;
    loginAttempts: number;
    lastLogin: Date | null;
    createdAt: Date;
}

const UserSchema = new Schema<IUser>({
    email: { type: String, required: true, unique: true },
    password: { type: String, required: true },
    role: { type: String, enum: ['user', 'admin', 'moderator'], default: 'user' },
    sessionToken: { type: String, default: null },
    resetToken: { type: String, default: null },
    resetTokenExpiry: { type: Date, default: null },
    mfaSecret: { type: String, default: null },
    mfaEnabled: { type: Boolean, default: false },
    loginAttempts: { type: Number, default: 0 },
    lastLogin: { type: Date, default: null },
    createdAt: { type: Date, default: Date.now }
});

export const User = mongoose.model<IUser>('User', UserSchema);
