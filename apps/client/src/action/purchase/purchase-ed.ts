"use server"

import { PurchaseEd } from "@/dummy/purchase/purchase-ed"
import type { PromptItemType } from "@/types/prompts/promptsType"

export async function getPurchaseEd(): Promise<PromptItemType[]> {
	const res: PromptItemType[] = await PurchaseEd
	// const res: ProfileMemberInfoType = await profileMemberInfoUndefineData

	//     const res = await fetch(`${process.env.API_BASE_URL}/v1/profile`, {
	//       method: 'GET',
	//       headers: {
	//         'Content-Type': 'application/json',
	//         Authorization: `Bearer ${auth.accessToken}`,
	//       },
	//       cache: 'no-cache',
	//     })

	return res
}
