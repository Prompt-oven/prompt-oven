import CredentialsProvider from "next-auth/providers/credentials"
import type { NextAuthOptions, User } from "next-auth"
import GoogleProvider from "next-auth/providers/google"
import NaverProvider from "next-auth/providers/naver"
import KakaoProvider from "next-auth/providers/kakao"
import { signInByAuth, signInByOAuth } from "@/action/auth/OAuthSignInAction.ts"
import { refreshAccessToken } from "@/action/auth/authTokenAction"
import type { ExtendedToken } from "@/types/auth/AuthToken"
import { logoutAuthMember } from "@/action/auth/memberManageAction"
import { getProfileImage } from "@/action/profile/getProfilePic"
import { encryptPasswordWithDH, destroyDHSession } from "@/action/auth/dhAction"

export const authOptions: NextAuthOptions = {
	session: {
		strategy: "jwt",
		maxAge: 24 * 60 * 60, // 24 hours
		updateAge: 6 * 24 * 60 * 60, // 6 * 24 hours
	},
	providers: [
		CredentialsProvider({
			name: "credentials",
			credentials: {
				email: { label: "email", type: "text" },
				password: { label: "password", type: "password" },
			},
			async authorize(credentials): Promise<User | null> {
				if (!credentials?.email || !credentials?.password) {
					return null
				}

				try {
					// Encrypt password using DH key exchange
					const { encryptedPassword, sessionId } = await encryptPasswordWithDH(credentials.password)
					// Call sign-in API with encrypted password
					const response = await signInByAuth({
						email: credentials.email,
						password: encryptedPassword,
						sessionId,
					})

					// Check if response.result is valid
					if (!response || !response.result) {
						console.error("Invalid response from sign-in API:", response)
						return null
					}
					// Cleanup: Destroy DH session after use
					await destroyDHSession(sessionId);

					const profileImage = await getProfileImage(response.result.memberUUID)
					
					return {
						accesstoken: response.result.accesstoken,
						refreshtoken: response.result.refreshtoken,
						email: credentials.email,
						nickname: response.result.nickname,
						memberUUID: response.result.memberUUID,
						role: response.result.role,
						profileImage: profileImage.picture || "",
						failed: false,
					};
				} catch (error) {
					console.error("Authentication error:", error)
					return null
				}
			},
		}),
		NaverProvider({
			clientId: process.env.NAVER_CLIENT_ID || "",
			clientSecret: process.env.NAVER_CLIENT_SECRET || "",
		}),
		KakaoProvider({
			clientId: process.env.KAKAO_CLIENT_ID || "",
			clientSecret: process.env.KAKAO_CLIENT_SECRET || "",
		}),
		GoogleProvider({
			clientId: process.env.GOOGLE_CLIENT_ID || "",
			clientSecret: process.env.GOOGLE_CLIENT_SECRET || "",
		}),
	],
	secret: process.env.NEXTAUTH_SECRET,
	callbacks: {
		async signIn({ user, account, profile }) {
			if (account?.provider === "credentials") {
				if (user) {
					return true;
				} else {
					return false;
				}
			}
			//소셜 로그인 공통 처리
			if (account?.provider) {
				console.log(`${account.provider} Sign-In detected:`, account, profile)

				let providerID: string;
				let email: string | undefined

				switch (account.provider) {
					case "google":
						providerID = account.id as string
						email = profile?.email || "";
						break;

					case "naver":
						providerID = account.id as string
						email = user.email || "";
						break;

					case "kakao":
						providerID = account.id as string
						email = user.email || "";
						break;

					default:
						console.error("Unsupported provider:", account.provider)
						return false;
				}

				// OAuth API 호출
				const response = await signInByOAuth({
					provider: account.provider,
					providerID,
					email,
				});

				if (response) {
					// eslint-disable-next-line no-console -- This is a client-side only log
					console.log(`${account.provider} OAuth API response:`, response)
					return true
				} else {
					// eslint-disable-next-line no-console -- This is a client-side only log
					console.error(`${account.provider} OAuth API failed:`, response)
					return '/sign-up';
				}
			}
			return true;
		},
		async jwt({ token, user }): Promise<ExtendedToken> {
			if (user) {
				token.accesstoken = user.accesstoken
				token.refreshtoken = user.refreshtoken
				token.tokenExpiration = Date.now() + 24 * 60 * 60 * 1000
			}
			if (Date.now() >= (token.tokenExpiration as number || 0)) {
				const refreshedToken = await refreshAccessToken(token.refreshtoken as string || "")
				if (refreshedToken.result) {
					const profileImage = await getProfileImage(user.memberUUID)
					token.profileImage = profileImage.picture || ""
					user.profileImage = profileImage.picture || ""

					token.accesstoken = refreshedToken.result.accessToken
					user.accesstoken = refreshedToken.result.accessToken

					token.role = refreshedToken.result.role
					user.role = refreshedToken.result.role

					token.nickname = refreshedToken.result.nickname
					user.nickname = refreshedToken.result.nickname

					token.tokenExpiration = Date.now() + 6 * 24 * 60 * 60 * 1000
				} else {
					await logoutAuthMember({
						Authorization: `Bearer ${token.accesstoken}`,
						Refreshtoken: token.refreshtoken as string,
					})
					token.accesstoken = null
					token.refreshtoken = null
					token.tokenExpiration = null
					token.error = "LoggedOut"
				}
			}
			return { ...token, ...user }
		},

		async session({ session, token }) {
			session.user = token
			return session
		},
		async redirect({ url, baseUrl }) {
			return url.startsWith(baseUrl) ? url : baseUrl
		},
	},
	pages: {
		signIn: "/sign-in",
		// error: "/error",
	},
}
