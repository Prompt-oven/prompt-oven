import type {
	OAuthSignInRequest,
	OAuthSignInResponse,
	OAuthUnRegisterRequest,
	SignInResponse,
} from "@/types/auth/OAuthType.ts"
import { actionHandler } from "@/action/actionHandler.ts"
import type { SignInType } from '@/types/auth/AuthMemberType'

// todo : 구현 마무리하기 -- 2024.11.12
export const unregisterByOAuth = async (
	req: OAuthUnRegisterRequest,
): Promise<void> => {
	await actionHandler<object>({
		name: "unregisterByOAuth",
		url: "/v1/auth/oauth/unregister",
		options: {
			headers: {
				"Content-Type": "application/json",
			},
			method: "POST",
			body: JSON.stringify(req),
			cache: "no-cache",
		},
	})
}

export const signInByOAuth = async (
	reqBody: OAuthSignInRequest,
): Promise<OAuthSignInResponse> => {
	return actionHandler<OAuthSignInResponse>({
		name: "signInByOAuth",
		url: "/v1/auth/social/login",
		options: {
			headers: {
				"Content-Type": "application/json",
			},
			method: "POST",
			body: JSON.stringify(reqBody),
			cache: "no-cache",
		},
	})
}

export const signInByAuth = async (credentials: SignInType): Promise<SignInResponse> => {
	return actionHandler<SignInResponse>({
		name: "signInByAuth",
		url: `/v2/auth/login`,
		options: {
			method: "POST",
			headers: {
				"Content-Type": "application/json",
				"X-Session-ID": credentials.sessionId,
			},
			body: JSON.stringify({
				username: credentials.email,
				password: credentials.password,
			}),
		},
	});
};
