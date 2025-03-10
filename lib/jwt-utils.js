import * as jose from 'jose';

class JWTUtils {
  static instance = null;

  constructor() {
    this.jwtAlgo = 'RS256';
    // Get keys from environment variables
    this.privateKey = process.env.JWT_PRIVATE_KEY || '';
    this.publicKey = process.env.JWT_PUBLIC_KEY || '';
    this.signingKey = null;
    this.verificationKey = null;

    if (!this.privateKey || !this.publicKey) {
      console.error('JWT keys not found in environment variables');
    }
  }

  static getInstance() {
    if (!JWTUtils.instance) {
      JWTUtils.instance = new JWTUtils();
    }
    return JWTUtils.instance;
  }

  async getSigningKey() {
    if (!this.signingKey) {
      if (!this.privateKey) {
        throw new Error('JWT private key not configured');
      }
      this.signingKey = await jose.importPKCS8(this.privateKey, this.jwtAlgo);
    }
    return this.signingKey;
  }

  async getVerificationKey() {
    if (!this.verificationKey) {
      if (!this.publicKey) {
        throw new Error('JWT public key not configured');
      }
      this.verificationKey = await jose.importSPKI(this.publicKey, this.jwtAlgo);
    }
    return this.verificationKey;
  }

  async encode(params) {
    try {
      const { token } = params;
      console.log(params);
      const signingKey = await this.getSigningKey();

      const encodedJWT = await new jose.SignJWT({
        ...token,
        aud: process.env.JWT_KID,
        claims: {
          userId: token.sub
        }
      })
        .setProtectedHeader({ alg: this.jwtAlgo, kid: process.env.JWT_KID })
        .setExpirationTime('30d') // 30 days
        .sign(signingKey);
      console.log(encodedJWT);
      return encodedJWT;
    } catch (error) {
      console.error('JWT encoding error:', error);
      throw error;
    }
  }

  async decode(params) {
    const { token } = params;
    if (!token) return null;

    try {
      const verificationKey = await this.getVerificationKey();

      const { payload } = await jose.jwtVerify(token, verificationKey, {
        algorithms: [this.jwtAlgo]
      });

      return payload;
    } catch (error) {
      console.error('JWT decoding error:', error);
      return null;
    }
  }
}

export default JWTUtils.getInstance();