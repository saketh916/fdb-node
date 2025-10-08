const mongoose = require('mongoose');

const SearchHistorySchema = new mongoose.Schema({
    userEmail: { type: String, required: true },
    searchUrl: { type: String, required: true },
    searchResponse: { type: Object, required: true },
    timestamp: { type: Date, default: Date.now }
});

module.exports = mongoose.model('SearchHistory', SearchHistorySchema);
