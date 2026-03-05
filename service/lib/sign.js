/**
 * Provides basic settings for the frontend
 */
const jwt = require('jsonwebtoken'); // Make sure this is installed
const { sysEnv } = require('@drumee/server-essentials');
const { credential_dir } = sysEnv();
const keyPath = resolve(credential_dir, 'onlyoffice/info.json');
const { readFileSync } = require('jsonfile');
const { token: jwt_secret } = readFileSync(keyPath);

/**
 * 
 * @param {*} conf 
 * @returns 
 */
export function signDocumentPayload(document, user, drumeeContext, canEdit = 0) {

  // In your session creation endpoint
  const confObject = {
    document,
    editorConfig: {
      mode: canEdit ? "edit" : "view",
      callbackUrl: callbackUrl,
      user
    },
    // Drumee data
    drumeeContext
  };

  // Sign the ENTIRE config as the token
  const token = jwt.sign(
    confObject,
    jwt_secret
  );

  // Add token to config sent to frontend
  confObject.token = token;

  return confObject;


}


export async function checkDocumentPaylod(ctx) {
  try {
    const { id } = ctx.request.query;

    // OPTION A: Validate via Authorization header (from ONLYOFFICE)
    const authHeader = ctx.get('Authorization');
    let validatedSession = null;

    if (!authHeader || !authHeader.startsWith('Bearer ')) {
      ctx.throw(401, 'Invalid authorization token');
    }
    const token = authHeader.substring(7);

    try {
      // Verify the token and extract payload
      const decoded = jwt.verify(token, jwt_secret);

      // The token payload contains the URL being requested
      // You can log or validate against this URL
      console.log('Token payload:', decoded);

      // Extract session info if available in token
      if (decoded.payload && decoded.payload.url) {
        // You can optionally validate that the requested URL matches
        // the one in the token
        const requestedUrl = `https://app.drumee.io/-/svc/media.orig?id=${id}`;
        if (decoded.payload.url !== requestedUrl) {
          console.warn('URL mismatch in token validation');
        }
      }

      // Mark that we've validated via token
      validatedSession = { method: 'jwt' };
    } catch (jwtError) {
      console.error('JWT validation failed:', jwtError.message);
      ctx.throw(401, 'Invalid authorization token');
    }

    // OPTION B: Fallback to query parameter validation (from signed URLs)
    if (!validatedSession) {
      const { key, expires, signature } = ctx.request.query;

      if (!key || !expires || !signature) {
        ctx.throw(401, 'Missing authentication parameters');
      }

      if (Date.now() > parseInt(expires)) {
        ctx.throw(401, 'URL has expired');
      }

      const expectedSignature = crypto
        .createHmac('sha256', process.env.DRUMEE_SECRET)
        .update(`${id}:${key}:${expires}`)
        .digest('hex');

      if (signature !== expectedSignature) {
        ctx.throw(401, 'Invalid signature');
      }

      validatedSession = await this.drumee.db.collection('onlyoffice_sessions').findOne({
        key: key,
        fileId: id
      });

      if (!validatedSession) {
        ctx.throw(404, 'Session not found');
      }
    }

    // --- At this point, request is authenticated ---
    // Apply Drumee's ACL based on the validated session/user

    // Get file from Drumee filesystem
    const fileInfo = await this.drumee.file.getInfo(id);

    // Check read permission using validated session
    const hasReadPermission = await this.checkReadPermission(
      validatedSession.userId,
      id
    );

    if (!hasReadPermission) {
      ctx.throw(403, 'Access denied');
    }

    const fileStream = await this.drumee.file.read(id);

    // Set response headers
    ctx.set('Content-Type', fileInfo.mimeType || 'application/octet-stream');
    ctx.set('Content-Disposition', `inline; filename="${encodeURIComponent(fileInfo.name)}"`);
    ctx.set('Content-Length', fileInfo.size);

    // Required CORS headers for ONLYOFFICE
    ctx.set('Access-Control-Allow-Origin', 'https://oo.drumee.io');
    ctx.set('Access-Control-Allow-Methods', 'GET, OPTIONS');
    ctx.set('Access-Control-Allow-Headers', 'Authorization, Content-Type');
    ctx.set('Access-Control-Allow-Credentials', 'true');

    // Stream the file
    ctx.body = fileStream;

  } catch (error) {
    console.error('Read endpoint error:', error);
    ctx.throw(error.status || 500, error.message);
  }
}
