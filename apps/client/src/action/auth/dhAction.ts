import { DHKeyExchange } from "@/lib/DHKeyExchange";

export const encryptPasswordWithDH = async (password: string) => {
    try {
        // Generate session ID
        const sessionId = crypto.randomUUID();

        // Create DH instance
        const dh = new DHKeyExchange();
                
        // Step 1: Initialize key exchange
        const res = await fetch(
            `${process.env.API_BASE_URL}/v2/auth/key-exchange/init`,
            {
                method: "POST",
                headers: {
                    "X-Session-ID": sessionId,
                    "Content-Type": "application/json",
                },
            }
        );

        if (!res.ok) {
            throw new Error(`Failed to initialize key exchange: ${res.status}`);
        }

        const rawData: unknown = await res.json();
        
        if (typeof rawData !== "object" || rawData === null || !("result" in rawData) || rawData.result === null || typeof rawData.result !== "string") {
            throw new Error("Invalid response format from key exchange init");
        }

        const serverPublicKey = rawData.result;
        
        // Step 2: Complete key exchange
        const completeRes = await fetch(
            `${process.env.API_BASE_URL}/v2/auth/key-exchange/complete`, 
            {
                method: "POST",
                headers: {
                    "X-Session-ID": sessionId,
                    "Content-Type": "text/plain",
                },
                body: dh.getPublicKey(),
            }
        );

        if (!completeRes.ok) {
            throw new Error("Failed to complete key exchange");
        }
        
        // Generate shared secret and encrypt password
        dh.computeSharedSecret(serverPublicKey);
        const encryptedPassword = dh.encryptPassword(password);
        
        return {
            encryptedPassword,
            sessionId
        };
    } catch (error) {
		// eslint-disable-next-line no-console -- 오류 출력
        console.error("DH encryption error:", error);
        throw error;
    }
}

export const destroyDHSession = async (sessionId: string): Promise<void> => {
    try {
        const res = await fetch(
            `${process.env.API_BASE_URL}/v2/auth/key-exchange/destroy`,
            {
                method: "POST",
                headers: {
                    "X-Session-ID": sessionId,
                    "Content-Type": "application/json",
                },
            }
        );

        if (!res.ok) {
            throw new Error("Failed to destroy DH session");
        }
    } catch (error) {
        // eslint-disable-next-line no-console -- 오류 출력
        console.error("Failed to destroy DH session:", error);
    }
};
