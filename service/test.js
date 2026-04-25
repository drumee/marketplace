const express = require('express');
const jwt = require('jsonwebtoken');
const router = express.Router();

router.post('/callback', async (req, res) => {
  let token = null;
  let callbackData = null;
  
  try {
    // 1. Extract token from header
    const authHeader = req.headers.authorization;
    if (authHeader && authHeader.startsWith('Bearer ')) {
      token = authHeader.substring(7);
    } else {
      // Some versions might put token in body
      token = req.body.token;
    }
    
    if (!token) {
      throw new Error('No token provided');
    }
    
    // 2. Verify token WITHOUT audience/issuer validation
    const decoded = jwt.verify(token, process.env.ONLYOFFICE_JWT_SECRET, {
      algorithms: ['HS256'],
      audience: false,  // Skip audience validation
      issuer: false,    // Skip issuer validation
      ignoreNotBefore: true
    });
    
    // 3. Extract the actual callback data
    // It might be in 'payload' or directly in the decoded token
    callbackData = decoded.payload || decoded;
    
    // 4. Log for debugging
    console.log('Callback received:', {
      status: callbackData.status,
      key: callbackData.key,
      hasUrl: !!callbackData.url,
      hasChangesUrl: !!callbackData.changesurl
    });
    
    // 5. Handle different statuses
    switch (callbackData.status) {
      case 2: // MustSave (normal save after closing)
      case 6: // MustForceSave (force save during editing)
        if (callbackData.url) {
          // Download the document using the SAME token
          const downloadResponse = await fetch(callbackData.url, {
            headers: {
              'Authorization': `Bearer ${token}`
            }
          });
          
          if (!downloadResponse.ok) {
            throw new Error(`Download failed: ${downloadResponse.status}`);
          }
          
          const documentBuffer = await downloadResponse.buffer();
          
          // Find session and save
          const session = await db.collection('onlyoffice_sessions').findOne({
            key: callbackData.key
          });
          
          if (session) {
            await drumee.file.write(session.fileId, documentBuffer, {
              metadata: {
                savedBy: session.userId,
                savedAt: new Date(),
                status: callbackData.status
              }
            });
            
            console.log(`Document ${session.fileId} saved successfully`);
          }
        }
        break;
        
      case 3: // Corrupted (error during save)
      case 7: // Force save error
        console.error('Document save error:', callbackData);
        // Log error but still acknowledge
        break;
        
      case 4: // Closed with no changes
        console.log('Document closed with no changes');
        break;
        
      case 1: // Editing in progress
        // Just acknowledge, no action needed
        break;
        
      default:
        console.log('Unhandled status:', callbackData.status);
    }
    
    // 6. ALWAYS return success to acknowledge receipt
    res.json({ error: 0 });
    
  } catch (error) {
    console.error('Callback processing error:', error);
    
    // Log token for debugging if available
    if (token) {
      try {
        // Try to decode without verification to see structure
        const unverified = jwt.decode(token);
        console.log('Unverified token structure:', Object.keys(unverified || {}));
      } catch (e) {
        // Ignore decode errors
      }
    }
    
    // Return error but don't expose details
    res.status(401).json({ error: 1, message: 'Authentication failed' });
  }
});