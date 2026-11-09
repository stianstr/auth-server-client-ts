export declare function base64urlEncode(buffer: ArrayBuffer): string;
export declare function generateCodeVerifier(): string;
export declare function generateCodeChallenge(verifier: string): Promise<string>;
export declare function generateState(): string;
