"use client"

import { useState } from "react"
import type { FieldValues } from "react-hook-form"
import { useForm } from "react-hook-form"
import { zodResolver } from "@hookform/resolvers/zod"
import { Button } from "@repo/ui/button"
import { signupSchemaObject } from "@/schema/auth.ts"
import { useAuthTimer } from "@/hooks/auth/useAuthTimer.ts"
import {
	registerAuthMember,
	verifyEmail,
	verifyNickname,
} from "@/action/auth/memberManageAction"
import type { RegisterOAuthMemberResponse } from "@/types/auth/memberRegisterType"
import {
	checkEmailVerificationCode,
	requestPasswordResetEmail,
} from "@/action/auth/forgotPasswardAction"
import SignUpField from "@/components/auth/molecule/SignUpField.tsx"
import SignUpTimerField from "@/components/auth/molecule/SignUpTimerField.tsx"
import SuccessModal from "@/components/common/atom/SuccessModal"
import ValidTermsCheckBox from "../molecule/TermsValidCheckBox"

function SignUpForm() {
	const [emailVerified, setEmailVerified] = useState(false)
	const {
		handleSubmit,
		register,
		watch,
		setError,
		clearErrors,
		setValue,
		formState: { errors },
	} = useForm({
		resolver: zodResolver(signupSchemaObject),
		mode: "onChange",
	})

	const signUpSchemaKeys = signupSchemaObject._def.schema.keyof().enum
	const email: string = watch(signUpSchemaKeys.email) as string
	const emailCode: string = watch(signUpSchemaKeys.emailCode) as string
	const nickName: string = watch(signUpSchemaKeys.nickname) as string
	const [showTimerField, setShowTimerField] = useState(true)
	const [successModalOpen, setSuccessModalOpen] = useState(false)
	const [modalMessage, setModalMessage] = useState<string | null>(null)
	const [modalCallback, setModalCallback] = useState<(() => void) | null>(null)

	const handleOnSubmitSuccess = async (data: FieldValues) => {
		if (!emailVerified) {
			setError(signUpSchemaKeys.emailCode, {
				type: "manual",
				message: "Email verification is required.",
			})
			return
		}
		const responseData = data as RegisterOAuthMemberResponse
		await registerAuthMember(responseData)
		showSuccessModal("Emailcode is validated", () => {
			window.location.href = "/sign-in"
		})
	}
	const handleOnSubmitFailure = () => {
		setError(signUpSchemaKeys.emailCode, {
			type: "manual",
			message: "Sign-in fail",
		})
	}
	// email validation
	const emailCodeValidationHandler = async () => {
		try {
			const response = await checkEmailVerificationCode({
				email,
				code: emailCode,
			})
			if (response.isSuccess && response.result) {
				clearErrors(signUpSchemaKeys.emailCode)
				setEmailVerified(true)
				setShowTimerField(false)
				showSuccessModal("Emailcode is validated")
			} else {
				setError(signUpSchemaKeys.emailCode, {
					type: "manual",
					message: "Invalid verification code.",
				})
			}
		} catch (error) {
			setError(signUpSchemaKeys.emailCode, {
				type: "manual",
				message: "Verification failed. Please try again.",
			})
		}
	}

	const emailValidationHandler = async () => {
		try {
			// Step 1: Verify email duplication
			const verifyResponse = await verifyEmail({ email })
			if (!verifyResponse.isSuccess || !verifyResponse.result) {
				setError(signUpSchemaKeys.email, {
					type: "manual",
					message: "Email is already taken. Please use a different email.",
				})
				return
			}
			// Step 2: Send email verification request
			await requestPasswordResetEmail({ email })
			clearErrors(signUpSchemaKeys.email) // Clear any existing errors
			setShowTimerField(false) // 타이머 필드를 초기화
			setTimeout(() => {
				setShowTimerField(true) // 새로 갱신
				startTimer() // 타이머 시작
			}, 0)
		} catch (error) {
			setError(signUpSchemaKeys.email, {
				type: "manual",
				message: "Failed to validate email. Please try again.",
			})
		}
	}
	const emailValidationTime = 180 // 3 minutes in seconds
	const [timeLeft, startTimer] = useAuthTimer({ emailValidationTime })
	// nickname validation
	const nickNameValidationHandler = async () => {
		try {
			const response = await verifyNickname({ nickname: nickName })
			if (response.isSuccess && response.result) {
				clearErrors(signUpSchemaKeys.nickname)
				showSuccessModal("Nickname is validated")
			} else {
				setError(signUpSchemaKeys.nickname, {
					type: "manual",
					message: "Nickname is already taken. Please choose another one.",
				})
			}
		} catch (error) {
			setError(signUpSchemaKeys.nickname, {
				type: "manual",
				message: "Failed to validate nickname. Please try again.",
			})
		}
	}

	//showmodal
	const showSuccessModal = (message: string, onConfirm?: () => void) => {
		setModalMessage(message)
		setSuccessModalOpen(true)
		setModalCallback(() => onConfirm || null) // 확인 버튼 콜백 저장
	}
	const closeSuccessModal = () => {
		setSuccessModalOpen(false)
		setModalMessage(null)
		if (modalCallback) modalCallback() // 콜백 실행
		setModalCallback(null) // 콜백 초기화
	}
	return (
		<div className="min-w-[500px] select-none gap-0 rounded border-none bg-[#252525] px-6 pb-12 pt-16 md:min-h-[780px] md:max-w-[650px] md:px-10 md:pb-16 md:pt-24">
			<div className="mb-5 flex h-fit flex-col justify-center gap-[5px] md:mb-14">
				<h1 className="text-center text-4xl font-bold text-white">
					Create Your Account
				</h1>
				<p className="text-center text-[16px] font-normal leading-[26px] text-[#C1C1C1]">
					Enter your details to create your account
				</p>
			</div>
			<form
				onSubmit={handleSubmit(handleOnSubmitSuccess, handleOnSubmitFailure)}>
				<div className="mb-11 flex h-fit w-full flex-col gap-5">
					{/* Email */}
					<SignUpField
						showButton
						labelText="Email"
						labelProps={{
							htmlFor: signUpSchemaKeys.email,
						}}
						buttonText="Validate"
						buttonProps={{
							disabled: Boolean(errors[signUpSchemaKeys.email]) || !email,
							type: "button",
							onClick: emailValidationHandler,
						}}
						inputProps={{
							id: signUpSchemaKeys.email,
							placeholder: "Email",
							...register(signUpSchemaKeys.email),
						}}
						errorProps={{
							name: signUpSchemaKeys.email,
							errors,
						}}
					/>

					{/* Email Validation */}
					{showTimerField && timeLeft !== null && !emailVerified ? ( // 인증되지 않았을 때만 렌더링
						<SignUpTimerField
							inputProps={{
								id: signUpSchemaKeys.emailCode,
								placeholder: "Email Validation Code",
								...register(signUpSchemaKeys.emailCode),
							}}
							buttonProps={{
								type: "button",
								disabled:
									timeLeft === 0 ||
									Boolean(errors[signUpSchemaKeys.emailCode]) ||
									!emailCode,
								onClick: emailCodeValidationHandler,
							}}
							buttonText="Check"
							errorProps={{
								name: signUpSchemaKeys.emailCode,
								errors,
							}}
							timeLeft={timeLeft}
						/>
					) : null}

					{/* Password */}
					<SignUpField
						labelText="Password"
						labelProps={{
							htmlFor: signUpSchemaKeys.password,
						}}
						inputProps={{
							type: "password",
							id: signUpSchemaKeys.password,
							placeholder: "Password",
							...register(signUpSchemaKeys.password),
						}}
						errorProps={{
							name: signUpSchemaKeys.password,
							errors,
						}}
					/>

					{/* password confirm */}
					<SignUpField
						labelText="Password connfirm"
						labelProps={{
							htmlFor: signUpSchemaKeys.passwordValidate,
						}}
						inputProps={{
							type: "password",
							id: signUpSchemaKeys.passwordValidate,
							placeholder: "Password Confirm",
							...register(signUpSchemaKeys.passwordValidate),
						}}
						errorProps={{
							name: signUpSchemaKeys.passwordValidate,
							errors,
						}}
					/>

					{/* Nickname */}
					<SignUpField
						showButton
						labelText="Nickname"
						labelProps={{
							htmlFor: signUpSchemaKeys.nickname,
						}}
						buttonText="Validate"
						buttonProps={{
							disabled: Boolean(errors[signUpSchemaKeys.nickname]) || !nickName,
							type: "button",
							onClick: nickNameValidationHandler,
						}}
						inputProps={{
							type: "text",
							id: signUpSchemaKeys.nickname,
							placeholder: "Nickname",
							...register(signUpSchemaKeys.nickname),
						}}
						errorProps={{
							name: signUpSchemaKeys.nickname,
							errors,
						}}
					/>

					<div className="flex items-center space-x-2">
						<ValidTermsCheckBox
							id="terms"
							name="terms"
							label="I accept the terms"
							register={register}
							setError={setError}
							clearErrors={clearErrors}
							errorProps={{
								name: "terms",
								errors,
							}}
							setValue={setValue}
						/>
					</div>
				</div>
				<SuccessModal isOpen={successModalOpen} onClose={closeSuccessModal}>
					<div>{modalMessage}</div>
				</SuccessModal>
				<div className="mb-8 flex h-fit w-full flex-col items-center gap-4">
					<Button
						type="submit"
						className="h-[50px] w-full rounded-[25px] !bg-[#A913F9] text-white hover:!bg-[#A913F9]/90">
						Sign Up
					</Button>
				</div>
			</form>
		</div>
	)
}

export default SignUpForm
