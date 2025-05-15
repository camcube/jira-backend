// server.js

// Load environment variables from .env file
require('dotenv').config();

const express = require('express');
const axios = require('axios');
const cors = require('cors');
const bodyParser = require('body-parser');
const multer = require('multer');
const session = require('express-session'); // Import express-session
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const path = require('path');
const FormData = require('form-data'); // Ensure form-data is imported
const authRoutes = require('./auth/authRoutes');
const { requireAuth, requireRole } = require('./auth/middleware');
const connectDB = require('./db');
const mongoose = require('mongoose');
const RepairStatus = require('./models/RepairStatus'); // NEW
const TicketPriority = require('./models/TicketPriority');


mongoose.connect(process.env.MONGODB_URI)


.then(() => console.log('✅ Connected to MongoDB'))
.catch(err => console.error('❌ MongoDB connection error:', err));

mongoose.connection.once('open', () => {
  console.log('🔗 Connected to DB name:', mongoose.connection.name);
});



const app = express();

// Access environment variables
const PORT = process.env.PORT || 3000;
const JIRA_BASE_URL = process.env.JIRA_BASE_URL;
const SESSION_SECRET = process.env.SESSION_SECRET;
const os = require('os');

// Get local IP address (used for CORS origin)
function getLocalIPAddress() {
  const interfaces = os.networkInterfaces();
  for (const iface of Object.values(interfaces)) {
    for (const details of iface) {
      if (details.family === 'IPv4' && !details.internal) {
        return details.address;
      }
    }
  }
  return 'localhost'; // fallback
}

const localIP = getLocalIPAddress();
const FRONTEND_ORIGINS = [
  'http://localhost:4200',
  'http://127.0.0.1:4200',
  'https://the-dashboard-d1f19.web.app', // ✅ your deployed frontend
];






console.log(`🔓 Allowed CORS Origin: ${FRONTEND_ORIGINS}`);


// Middleware Configuration

// Security Middlewares
app.use(helmet());

// Rate Limiting to prevent brute-force attacks
const limiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 100, // Limit each IP to 100 requests per windowMs
});
//app.use(limiter);

// CORS Configuration
app.use(cors({
  origin: function (origin, callback) {
    if (!origin || FRONTEND_ORIGINS.includes(origin)) {
      callback(null, true);
    } else {
      callback(new Error('CORS origin not allowed: ' + origin));
    }
  },
  credentials: true,
}));


// Body Parser Middleware
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));


// Session Middleware
app.use(session({
  name: 'connect.sid',
  secret: SESSION_SECRET,
  resave: false,
  saveUninitialized: false,
  cookie: {
    httpOnly: true,
    secure: false,        // use true only if HTTPS
    sameSite: 'lax',     // IMPORTANT: allows cookies in cross-origin requests
    maxAge: 8 * 60 * 60 * 1000,
  },  
}));


app.use((req, res, next) => {
  res.on('finish', () => {
    const setCookie = res.getHeader('Set-Cookie');
    console.log('DEBUG: Set-Cookie Header:', setCookie);
  });
  next();
});


app.use((req, res, next) => {
  console.log('\n📥 Incoming Request');
  console.log(`→ Method: ${req.method}`);
  console.log(`→ URL: ${req.originalUrl}`);
  console.log(`→ Cookie Header:`, req.headers.cookie || '(none)');
  console.log(`→ Session ID: ${req.sessionID}`);
  console.log('→ Session Data:', req.session);
  next();
});



// Multer Configuration for File Uploads
const storage = multer.memoryStorage();
const upload = multer({ storage });




// --- Authentication Endpoints ---

// Login Endpoint
app.post('/login', async (req, res) => {
  const { email, apiKey } = req.body;

  if (!email || !apiKey) {
    console.log('Login Attempt Failed: Missing email or API Key.');
    return res.status(400).json({ message: 'Email and API Key are required.' });
  }

  

  // Create Base64-encoded credentials
  const credentials = `${email}:${apiKey}`;
  const encodedCredentials = Buffer.from(credentials).toString('base64');



  try {
    // Verify credentials by calling Jira's /myself endpoint
    const response = await axios.get(`${JIRA_BASE_URL}/myself`, {
      headers: {
        Authorization: `Basic ${encodedCredentials}`,
        'Accept': 'application/json',
      },
    });

    // Log the response from Jira's /myself endpoint
    console.log('Jira /myself Response:', response.data);

    if (response.status === 200) {
      // Store credentials in session
      req.session.user = {
        email,
        encodedCredentials,
      };
      console.log('Login successful. Session created.');
      return res.json({ message: 'Login successful.' });
    } else {
      console.log('Login Failed: Invalid credentials.');
      return res.status(401).json({ message: 'Invalid credentials.' });
    }
  } catch (error) {
    // Log detailed error information
    if (error.response) {
      console.error('Login Error Response:', error.response.data);
      console.error('Status Code:', error.response.status);
    } else {
      console.error('Login Error:', error.message);
    }
    return res.status(401).json({ message: 'Invalid credentials.' });
  }
});

// Logout Endpoint
app.post('/logout', (req, res) => {
  req.session.destroy((err) => {
    if (err) {
      console.error('Logout Error:', err);
      return res.status(500).json({ message: 'Logout failed.' });
    }
    res.clearCookie('connect.sid'); // Name might vary based on session configuration
    return res.json({ message: 'Logout successful.' });
  });
});

// --- Authentication Middleware ---

function isAuthenticated(req, res, next) {
  if (req.session && req.session.user && req.session.user.encodedCredentials) {
    console.log(`Authenticated Request by: ${req.session.user.email}`);
    next();
  } else {
    console.log('Unauthorized Request Detected.');
    res.status(401).json({ message: 'Unauthorized. Please log in.' });
  }
}

// --- Protected Jira API Endpoints ---

// API endpoint to check server status
app.get('/api/jira', (req, res) => {
  res.send('Server is running and ready to accept requests!');
});

// Fetch current user info from Jira
app.get('/api/jira/myself', isAuthenticated, async (req, res) => {
  try {
    const { encodedCredentials } = req.session.user;

    const response = await axios.get(`${JIRA_BASE_URL}/myself`, {
      headers: {
        Authorization: `Basic ${encodedCredentials}`,
        'Accept': 'application/json',
      },
    });

    res.json(response.data);
  } catch (error) {
    console.error('Error fetching user info:', error.response?.data || error.message);
    res.status(error.response?.status || 500).send(error.response?.data || error.message);
  }
});

// API endpoint to fetch Jira tickets based on a JQL query (pagination enabled)
app.get('/api/jira/search', isAuthenticated, async (req, res) => {
  try {
    const { jql } = req.query;
    const { encodedCredentials } = req.session.user;

    let allIssues = [];
    let startAt = 0;
    let maxResults = 100; // Set the max Jira allows (1000 is max, but 100 is safer)
    let total = 0;

    do {
      const response = await axios.get(`${JIRA_BASE_URL}/search`, {
        headers: {
          Authorization: `Basic ${encodedCredentials}`,
          'Content-Type': 'application/json',
        },
        params: {
          jql: jql,
          maxResults: maxResults,
          startAt: startAt,
        },
      });

      // Push fetched issues into the array
      allIssues.push(...response.data.issues);
      total = response.data.total; // Get total count from response
      startAt += maxResults; // Move to next batch

    } while (allIssues.length < total);

    // Extract KQW keys for logging
    const kqwKeys = allIssues.map(issue => issue.key);
    console.log('All KQW Tickets Pulled from Backend:', kqwKeys);

    res.json({ total: allIssues.length, issues: allIssues });
  } catch (error) {
    console.error('Error fetching Jira tickets:', error.response?.data || error.message);
    res.status(error.response?.status || 500).send(error.response?.data || error.message);
  }
});


// API endpoint to fetch comments for a specific Jira issue
app.get('/api/jira/issue/:issueKey/comment', isAuthenticated, async (req, res) => {
  try {
    const { issueKey } = req.params;
    const { encodedCredentials } = req.session.user;

    const response = await axios.get(
      `${JIRA_BASE_URL}/issue/${issueKey}/comment`,
      {
        headers: {
          Authorization: `Basic ${encodedCredentials}`,
          'Content-Type': 'application/json',
        },
      }
    );

    res.json(response.data);
  } catch (error) {
    console.error('Error fetching comments:', error.response?.data || error.message);
    res.status(error.response?.status || 500).send(error.response?.data || error.message);
  }
});

// API endpoint to fetch detailed issue information, including attachments
app.get('/api/jira/:issueKey', isAuthenticated, async (req, res) => {
  try {
    const { issueKey } = req.params;
    const { encodedCredentials } = req.session.user;

    const response = await axios.get(`${JIRA_BASE_URL}/issue/${issueKey}`, {
      headers: {
        Authorization: `Basic ${encodedCredentials}`,
        'Content-Type': 'application/json',
      },
    });
    console.log('Raw comments response from Jira from server.js:', response.data);
    response.data.fields.comments.forEach((comment) => {
      console.log(`Author for comment from server.js ${comment.id}:`, comment.author);
    });
    res.json(response.data);
  } catch (error) {
    console.error('Error fetching issue details:', error.response?.data || error.message);
    res.status(error.response?.status || 500).send(error.response?.data || error.message);
  }
});

// API endpoint to fetch attachments for a specific Jira issue
app.get('/api/jira/issue/:issueKey/attachments', isAuthenticated, async (req, res) => {
  try {
    const { issueKey } = req.params;
    const { encodedCredentials } = req.session.user;

    const response = await axios.get(`${JIRA_BASE_URL}/issue/${issueKey}`, {
      headers: {
        Authorization: `Basic ${encodedCredentials}`,
        'Content-Type': 'application/json',
      },
    });

    // Extract attachments from the issue fields
    const attachments = response.data.fields.attachment || [];
    res.json({ attachments });
  } catch (error) {
    console.error('Error fetching attachments:', error.response?.data || error.message);
    res.status(error.response?.status || 500).send(error.response?.data || error.message);
  }
});

// --- Multer Configuration for File Uploads ---

// Upload an attachment to a Jira issue
app.post('/api/jira/issue/:issueKey/attachments', isAuthenticated, upload.single('file'), async (req, res) => {
  try {
    const { issueKey } = req.params;
    const file = req.file;
    const { encodedCredentials } = req.session.user;

    if (!file) {
      return res.status(400).send('No file uploaded.');
    }

    // Convert the buffer to a Blob-like object using FormData
    const formData = new FormData();
    formData.append('file', file.buffer, file.originalname);

    const response = await axios.post(
      `${JIRA_BASE_URL}/issue/${issueKey}/attachments`,
      formData,
      {
        headers: {
          Authorization: `Basic ${encodedCredentials}`,
          'X-Atlassian-Token': 'no-check',
          ...formData.getHeaders(), // Set proper headers for FormData
        },
      }
    );

    res.status(200).json(response.data);
  } catch (error) {
    console.error('Error uploading attachment to Jira:', error.response?.data || error.message);
    res.status(error.response?.status || 500).send(error.response?.data || error.message);
  }
});

// Delete an attachment from a Jira issue
app.delete('/api/jira/issue/:issueKey/attachments/:attachmentId', isAuthenticated, async (req, res) => {
  try {
    const { attachmentId } = req.params;
    const { encodedCredentials } = req.session.user;

    const response = await axios.delete(`${JIRA_BASE_URL}/attachment/${attachmentId}`, {
      headers: {
        Authorization: `Basic ${encodedCredentials}`,
        'Content-Type': 'application/json',
      },
    });

    res.status(200).json({ message: 'Attachment deleted successfully.' });
  } catch (error) {
    console.error('Error deleting attachment:', error.response?.data || error.message);
    res.status(error.response?.status || 500).send(error.response?.data || error.message);
  }
});

// Fetch the content of a specific attachment
app.get('/api/jira/attachment/content/:attachmentId', isAuthenticated, async (req, res) => {
  try {
    const { attachmentId } = req.params;
    const { encodedCredentials } = req.session.user;

    console.log(`Fetching content for attachment ID: ${attachmentId}`);
    const response = await axios.get(`${JIRA_BASE_URL}/attachment/content/${attachmentId}`, {
      headers: {
        Authorization: `Basic ${encodedCredentials}`,
        'Content-Type': 'application/json',
      },
      responseType: 'arraybuffer', // Ensures we receive raw binary data for attachments
    });

    // Send the binary data back as-is
    res.setHeader('Content-Type', 'application/octet-stream'); // General binary stream
    res.status(200).send(response.data);
  } catch (error) {
    console.error('Error fetching attachment content:', error.response?.data || error.message);
    res.status(error.response?.status || 500).send({
      message: 'Failed to fetch attachment content.',
      details: error.response?.data || error.message,
    });
  }
});

// Post a comment to a Jira issue
app.post('/api/jira/issue/:issueKey/comment', isAuthenticated, async (req, res) => {
  try {
    const { issueKey } = req.params;
    const { body } = req.body; // Expect comment body in the request
    const { encodedCredentials } = req.session.user;

    console.log('[MENTION-DEBUG] Received comment body:', JSON.stringify(body));

   // If the front end already provided a doc with mention nodes, use it as-is.
   // Otherwise, wrap the raw text in a minimal doc.
   let docPayload;
   if (body && body.type === 'doc') {
     // The front end sent an actual doc structure
     docPayload = body;
   } else {
     // The front end just sent a string (or something else), so wrap in doc
     docPayload = {
       type: 'doc',
       version: 1,
       content: [
         {
           type: 'paragraph',
           content: [
             {
               type: 'text',
               text: body,
             },
           ],
         },
       ],
     };
   }

   console.log('[MENTION-DEBUG] Final docPayload to Jira:', JSON.stringify(docPayload));

    const response = await axios.post(
      `${JIRA_BASE_URL}/issue/${issueKey}/comment`,
      { body: docPayload },
      {
        headers: {
          Authorization: `Basic ${encodedCredentials}`,
          'Content-Type': 'application/json',
        },
      }
    );

    res.status(201).json(response.data);
  } catch (error) {
    console.error('Error posting comment:', error.response?.data || error.message);
    res.status(error.response?.status || 500).send(error.response?.data || error.message);
  }
});

// Update a specific comment
app.put('/api/jira/issue/:issueKey/comment/:commentId', isAuthenticated, async (req, res) => {
  try {
    const { issueKey, commentId } = req.params;
    const updatedBody = req.body; // Expecting the updated comment body in the request
    const { encodedCredentials } = req.session.user;

    const response = await axios.put(
      `${JIRA_BASE_URL}/issue/${issueKey}/comment/${commentId}`,
      updatedBody,
      {
        headers: {
          Authorization: `Basic ${encodedCredentials}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      }
    );

    res.status(response.status).json(response.data);
  } catch (error) {
    console.error('Error updating comment:', error.response?.data || error.message);
    res.status(error.response?.status || 500).send(error.response?.data || error.message);
  }
});

// Delete a specific comment
app.delete('/api/jira/issue/:issueKey/comment/:commentId', isAuthenticated, async (req, res) => {
  try {
    const { issueKey, commentId } = req.params;
    const { encodedCredentials } = req.session.user;

    const response = await axios.delete(
      `${JIRA_BASE_URL}/issue/${issueKey}/comment/${commentId}`,
      {
        headers: {
          Authorization: `Basic ${encodedCredentials}`,
          'Content-Type': 'application/json',
          'Accept': 'application/json',
        },
      }
    );

    res.status(response.status).json({ message: 'Comment deleted successfully.' });
  } catch (error) {
    console.error('Error deleting comment:', error.response?.data || error.message);
    res.status(error.response?.status || 500).send(error.response?.data || error.message);
  }
});


// Route to search for users by name (for @mention functionality)
app.get('/api/jira/user/search', isAuthenticated, async (req, res) => {
  try {
    const searchQuery = req.query.query;
    const { encodedCredentials } = req.session.user;

    // DEBUG: Log the query
    console.log(`[MENTION-DEBUG] Searching for users with query: "${searchQuery}"`);

    const jiraUrl = `${JIRA_BASE_URL}/user/search?query=${encodeURIComponent(searchQuery)}`;
    const response = await axios.get(jiraUrl, {
      headers: {
        Authorization: `Basic ${encodedCredentials}`,
        Accept: 'application/json',
      },
    });

    // DEBUG: Log how many users returned (if any)
    console.log(`[MENTION-DEBUG] Jira returned ${response.data.length} users for "${searchQuery}"`);

    res.json(response.data);
  } catch (error) {
    console.error('Error searching users in Jira:', error.response?.data || error.message);
    res.status(error.response?.status || 500).send(error.response?.data || error.message);
  }
});

// JWT-based login route
app.use('/api/auth', authRoutes);
// Test protected JWT routes
app.get('/api/test/tech', requireAuth, requireRole('technician'), (req, res) => {
  res.json({ message: `Hello Technician ${req.user.username}` });
});

app.get('/api/test/admin', requireAuth, requireRole('admin'), (req, res) => {
  res.json({ message: `Welcome Admin ${req.user.username}` });
});

app.post('/api/rma/status/:kqw', async (req, res) => {
  const { kqw } = req.params;
  const { status } = req.body;

  console.log(`[MongoDB] Received POST for ${kqw} with status: ${status}`);

  if (!['UNSTARTED', 'IN PROGRESS', 'AWAITING QC', 'REWORK'].includes(status)) {
    console.warn('[MongoDB] Invalid status:', status);
    return res.status(400).json({ message: 'Invalid status value.' });
  }

  try {
    const updated = await RepairStatus.findOneAndUpdate(
      { kqw },
      { status, updatedAt: new Date() },
      { upsert: true, new: true }
    );
    console.log('[MongoDB] Upserted entry:', updated);
    res.json(updated);
  } catch (err) {
    console.error('[MongoDB] Failed to save:', err);
    res.status(500).json({ message: 'Failed to update status.' });
  }
});



app.get('/api/rma/status/:kqw', async (req, res) => {
  const { kqw } = req.params;

  console.log(`🔎 [DB GET] Checking status for KQW ${kqw}`);

  try {
    const entry = await RepairStatus.findOne({ kqw });
    if (!entry) {
      console.log(`🚫 [DB GET] No entry found for KQW ${kqw}`);
      return res.status(404).json({ message: 'No status found for this ticket.' });
    }

    console.log(`📦 [DB GET] Status found:`, entry);
    res.json(entry);
  } catch (err) {
    console.error('❌ [DB GET] MongoDB lookup error:', err);
    res.status(500).json({ message: 'Failed to fetch status.' });
  }
});


// Express route in your backend to get a single Jira issue by key
app.get('/api/jira/issue/:key', isAuthenticated, async (req, res) => {
  const issueKey = req.params.key;
  const { encodedCredentials } = req.session.user;

  try {
    const response = await axios.get(`${JIRA_BASE_URL}/issue/${issueKey}`, {
      headers: {
        Authorization: `Basic ${encodedCredentials}`,
        'Accept': 'application/json'
      }
    });

    res.json(response.data);
  } catch (err) {
    console.error(`Failed to fetch issue ${issueKey}:`, err.response?.data || err.message);
    res.status(err.response?.status || 500).json({ error: 'Failed to fetch Jira issue' });
  }
});


const WorkOrder = require('./models/WorkOrder');

// GET work order
app.get('/api/workorder/:kqw', async (req, res) => {
  try {
    const doc = await WorkOrder.findOne({ kqw: req.params.kqw });
    res.json(doc || { kqw: req.params.kqw, lineItems: [] });
  } catch (err) {
    res.status(500).json({ message: 'Failed to fetch work order' });
  }
});

// POST/PUT work order
app.post('/api/workorder/:kqw', async (req, res) => {
  try {
    const { lineItems } = req.body;
    const updated = await WorkOrder.findOneAndUpdate(
      { kqw: req.params.kqw },
      { lineItems, updatedAt: new Date() },
      { upsert: true, new: true }
    );
    res.json(updated);
  } catch (err) {
    res.status(500).json({ message: 'Failed to save work order' });
  }
});

app.get('/api/repair-priorities', async (req, res) => {
  try {
    const all = await TicketPriority.find({}, { _id: 0, kqw: 1, priority: 1 });
    const map = {};
    for (let p of all) map[p.kqw] = p.priority;
    res.json(map);
  } catch (err) {
    console.error('[MongoDB] Error fetching priorities:', err);
    res.status(500).json({ message: 'Failed to load priorities.' });
  }
});

app.post('/api/repair-priorities/:kqw', async (req, res) => {
  const { kqw } = req.params;
  const { newPriority } = req.body;

  if (!Number.isInteger(newPriority) || newPriority < 1) {
    return res.status(400).json({ message: 'Invalid priority number.' });
  }

  try {
    const all = await TicketPriority.find().sort({ priority: 1 });
    const existing = all.find(t => t.kqw === kqw);

    const filtered = all.filter(t => t.kqw !== kqw);

    filtered.splice(newPriority - 1, 0, { kqw, priority: newPriority }); // insert updated

    const updates = await Promise.all(
      filtered.map((entry, idx) =>
        TicketPriority.findOneAndUpdate(
          { kqw: entry.kqw },
          { priority: idx + 1, updatedAt: new Date() },
          { upsert: true, new: true }
        )
      )
    );

    res.json({ message: 'Priorities updated.', updated: updates });
  } catch (err) {
    console.error('[MongoDB] Priority update error:', err);
    res.status(500).json({ message: 'Priority update failed.' });
  }
});


// Root route to verify deployment is working
app.get('/', (req, res) => {
  res.send('✅ Backend is live and ready to receive requests!');
});



// Start the server
app.listen(PORT, '0.0.0.0', () => {
  console.log(`Server is running on port:${PORT}`);
});


 