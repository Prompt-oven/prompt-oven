import { getCategory } from "@/action/prompts/getCategoryData"
import { getPromptList } from "@/action/prompts/getPromptsData"
import PromptsTemplate from "@/components/prompts/template/PromptsTemplate"

export default async function Marketplace() {
	const promptData = await getPromptList()
	const categoryList = await getCategory()

	return (
		<main className="container mx-auto bg-[#111111] py-1">
			<PromptsTemplate promptData={promptData} categoryList={categoryList} />
		</main>
	)
}
