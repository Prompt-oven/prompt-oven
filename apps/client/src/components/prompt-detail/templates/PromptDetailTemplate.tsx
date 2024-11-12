import type { PromptDetailInfoType } from "@/types/prompt-detail/promptDetailType"
import type { PromptReviewType } from "@/types/review/reviewType"
import PromptDetailInfo from "../organisms/PromptDetailInfo"
import PromptDetailReviewCount from "../organisms/PromptDetailReviewCount"
import PromptDetailThumbnail from "../organisms/PromptDetailThumbnail"
import PromptReviewContents from "../organisms/PromptReviewContents"

interface PromptDetailProps {
	productDetail: PromptDetailInfoType
	productReview: PromptReviewType
}

export default function PromptDetailTemplate({
	productDetail,
	productReview,
}: PromptDetailProps) {
	return (
		<section className="flex flex-col gap-16">
			<div className="container mx-auto rounded-lg">
				<div className="flex gap-20 sm:flex-col lg:flex-row">
					<PromptDetailThumbnail
						thumbnailUrl={productDetail.thumbnailUrl}
						productUUID={productDetail.productUUID}
					/>

					<div className="flex min-h-[800px] flex-grow flex-col gap-12">
						<PromptDetailInfo productDetail={productDetail} />
					</div>
				</div>
			</div>

			<div className="container mx-auto flex flex-col gap-8 text-white">
				<PromptDetailReviewCount reviewCount={productReview.content.length} />
				<PromptReviewContents productReview={productReview} />
			</div>
		</section>
	)
}