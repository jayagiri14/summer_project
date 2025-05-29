const mongoose = require('mongoose');

const codeSchema = new mongoose.Schema({
    email: {
        type: mongoose.SchemaTypes.String,
        required: true,
        unique: true
    },
    code: {
        type: mongoose.SchemaTypes.String,
        required: true,
    },
    createdAt: {
        type: Date,
        default: Date.now,
        expires: 30 // Document will expire 30 seconds after creation
    }
}, { timestamps: true });

module.exports = mongoose.model('Code', codeSchema);