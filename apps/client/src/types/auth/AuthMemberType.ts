// 계정정보
export interface AuthMemberType {
	accessToken: string
	refreshToken: string
	nickname: string
	signinEmail: string
}

//로그인
export interface SignInType {
	email: string
	password: string
	sessionId: string
}

// 로그아웃 헤더
export interface LogoutRequest {
  Authorization: string;
  Refreshtoken: string;
}

// 로그아웃 response
export interface LogoutResponse {
  httpStatus: string;
  isSuccess: boolean;
  message: string;
  result: object;
}

// nickname verify
export interface VerifyNicknameRequest {
  nickname: string;
}

// nickname verify response
export interface VerifyNicknameResponse {
  httpStatus: string;
  isSuccess: boolean;
  message: string;
  result: boolean;
}

// 이메일 verify request
export interface VerifyEmailRequest {
  email: string;
}

// 이메일 verify response
export interface VerifyEmailResponse {
  httpStatus: string;
  isSuccess: boolean;
  message: string;
  result: boolean;
}

// nickname 변경 request
export interface UpdateNicknameRequest {
  memberUUID: string;
  nickname: string;
}

// nickname 변경 response
export interface UpdateNicknameResponse {
  httpStatus: string;
  isSuccess: boolean;
  message: string;
  result: Record<string, unknown>;
}