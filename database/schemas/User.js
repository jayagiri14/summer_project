const mongoose = require('mongoose');

const userSchema = new mongoose.Schema({
    email: {
        type: mongoose.SchemaTypes.String,
        required: true,
        unique: true
    },
    name: {
        type: mongoose.SchemaTypes.String,
        required: true,
    },
    password: {
        type: mongoose.SchemaTypes.String,
        required: false, // <-- Not required for Google users
    },
    verified: {
        type: mongoose.SchemaTypes.Boolean,
        required: false,
        default: false // <-- Optional: default to false
    },
}, { timestamps: true });

module.exports = mongoose.model('User', userSchema);