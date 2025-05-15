// models/WorkOrder.js
const mongoose = require('mongoose');

const LineItemSchema = new mongoose.Schema({
  itemNumber: { type: String, required: true },
  quantity: { type: Number, required: true }
});

const WorkOrderSchema = new mongoose.Schema({
  kqw: { type: String, required: true, unique: true },
  lineItems: [LineItemSchema],
  updatedAt: { type: Date, default: Date.now },
});

module.exports = mongoose.model('WorkOrder', WorkOrderSchema);
