// models/TicketPriority.js
const mongoose = require('mongoose');

const TicketPrioritySchema = new mongoose.Schema({
  kqw: { type: String, required: true, unique: true },
  priority: { type: Number, required: true },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('TicketPriority', TicketPrioritySchema);
