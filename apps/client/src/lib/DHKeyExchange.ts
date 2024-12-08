import { Buffer } from "node:buffer"
import crypto from "node:crypto"

export class DHKeyExchange {
	private dh: crypto.DiffieHellman
	private sharedSecret: Buffer | null = null

	constructor() {
		// Use the same parameters as the Java side
		const prime = Buffer.from(
			'FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1' +
			'29024E088A67CC74020BBEA63B139B22514A08798E3404DD' +
			'EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245' +
			'E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED' +
			'EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D' +
			'C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F' +
			'83655D23DCA3AD961C62F356208552BB9ED529077096966D' +
			'670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B' +
			'E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9' +
			'DE2BCBF6955817183995497CEA956AE515D2261898FA0510' +
			'15728E5A8AACAA68FFFFFFFFFFFFFFFF', 'hex');
		const generator = Buffer.from('02', 'hex');
		
		this.dh = crypto.createDiffieHellman(prime, generator);
		this.dh.generateKeys();
	}

	// Get public key to send to server
	getPublicKey(): string {
		const publicKeyBuffer = this.dh.getPublicKey();
		
		// Create ASN.1 DER encoding for the public key
		const derPrefix = Buffer.from([
			0x30, // SEQUENCE
			0x82, // Length field, 2 bytes
			0x01, // Length high byte
			0x22, // Length low byte (290 bytes total)
			0x30, // SEQUENCE
			0x82,
			0x01,
			0x1D, // Length of remaining sequence
			0x02, // INTEGER
			0x81, // Length field, 1 byte
			0x81  // Length (129 bytes)
		]);
		
		// Combine DER prefix with the public key
		const derPublicKey = Buffer.concat([
			derPrefix,
			Buffer.from([0x00]), // Prepend 0x00 to ensure positive integer
			publicKeyBuffer
		]);
		
		return derPublicKey.toString('base64');
	}

	// Generate shared secret from server's public key
	computeSharedSecret(serverPublicKeyBase64: string): void {
		const serverPublicKey = Buffer.from(serverPublicKeyBase64, 'base64');
		this.sharedSecret = this.dh.computeSecret(serverPublicKey);
	}

	// Encrypt password using shared secret
	encryptPassword(password: string): string {
		if (!this.sharedSecret) {
			throw new Error("Shared secret not computed yet");
		}

		// Generate key from shared secret (same as server)
		const key = crypto.createHash("sha256").update(this.sharedSecret).digest();

		// Generate random IV
		const iv = crypto.randomBytes(16);

		// Create cipher with PKCS7 padding (compatible with Java's PKCS5Padding)
		const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
		cipher.setAutoPadding(true);  // Ensure PKCS7 padding is enabled

		// Convert password to Buffer to ensure consistent encoding
		const passwordBuffer = Buffer.from(password, 'utf8');

		// Encrypt
		const encryptedBuffer = Buffer.concat([
			cipher.update(passwordBuffer),
			cipher.final()
		]);

		// Combine IV and encrypted data
		const combined = Buffer.concat([iv, encryptedBuffer]);
		
		// Return as base64
		return combined.toString('base64');
	}
}