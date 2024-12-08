export interface OAuthUnRegisterRequest {
	provider: string
	providerId: string
	memberUUID: string
}

export interface OAuthRegisterRequest {
	provider: string
	providerId: string
	memberUUID: string
}

export interface OAuthSignInRequest {
	provider: string
	providerID: string
	email: string
}

// Base response type for auth results
export interface AuthResponse {
	result: {
		accesstoken: string
		refreshtoken: string
		nickname: string
		role: string
		memberUUID: string
	}
}

// OAuth specific response adds failed flag
export interface OAuthSignInResponse extends Omit<AuthResponse['result'], 'role'> {
	failed: boolean
}

// Regular sign-in response
export interface SignInResponse {
	result: {
		accesstoken: string
		refreshtoken: string
		nickname: string
		role: string
		memberUUID: string
	}
}