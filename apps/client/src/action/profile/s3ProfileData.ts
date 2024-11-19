"use server"

import { v4 as uuidv4 } from "uuid"
import type { S3ResponseType } from "@/types/profile/profileModifyTypes"

export const uploadProfileImage = async (
	avatarUrl: string,
): Promise<S3ResponseType> => {
	"use server"
	try {
		// URL에서 이미지를 가져와 Blob으로 변환
		const response = await fetch(avatarUrl)
		if (!response.ok) {
			return { isSuccess: false, imageUrl: undefined }
		}
		const blob = await response.blob()

		const uuidFileName = `${uuidv4()}.png`

		const file = new File([blob], uuidFileName, {
			type: "image/png", // Blob의 MIME 타입을 지정
		})

		const uploadFormData = new FormData()
		uploadFormData.append("img", file)

		const result = await fetch(
			`${process.env.NEXTAUTH_URL}/api/upload/profile`,
			{
				method: "POST",
				body: uploadFormData,
			},
		).then((res) => res.json())

		if ((result as { message: string }).message === "OK") {
			return { isSuccess: true, imageUrl: uuidFileName }
		}
		return { isSuccess: false, imageUrl: undefined }
	} catch (error) {
		return { isSuccess: false, imageUrl: undefined }
	}
}
