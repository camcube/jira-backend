const mongoose = require('mongoose');

const repairStatusSchema = new mongoose.Schema({
  kqw: { type: String, required: true, unique: true },
  status: { type: String, enum: ['UNSTARTED', 'IN PROGRESS', 'AWAITING QC', 'REWORK'], default: 'UNSTARTED' },
  updatedAt: { type: Date, default: Date.now }
});

module.exports = mongoose.model('RepairStatus', repairStatusSchema);
