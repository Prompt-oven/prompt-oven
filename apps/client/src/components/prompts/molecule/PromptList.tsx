import PromptCard from "@/components/common/organism/PromptCard"
import type { PromptItemType } from "@/types/prompts/promptsType"

interface PromptsListProps {
	promptList: PromptItemType[]
}

export default function PromptList({ promptList }: PromptsListProps) {
	return (
		<div>
			<ul className="grid grid-cols-1 gap-8 sm:grid-cols-2 lg:grid-cols-3 xl:grid-cols-4 2xl:grid-cols-5">
				{promptList.length > 0
					? promptList.map((item) => (
							<PromptCard productInfo={item} key={item.productUuid} />
						))
					: null}
			</ul>
		</div>
	)
}
