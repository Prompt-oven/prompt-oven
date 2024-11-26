import type { FavoriteType } from "@/types/favorite/favoriteTypes"
import FavoriteList from "../molecule/FavoriteList"
import FavoriteCountBar from "../molecule/FavoriteCountBar"

interface FavoriteContainerProps {
	favoriteList: FavoriteType[]
}

export default function FavoriteContainer({
	favoriteList,
}: FavoriteContainerProps) {
	return (
		<div className="flex flex-col gap-8">
			<FavoriteCountBar favoriteCount={favoriteList.length} />
			<div className="mx-auto mb-16 flex flex-col gap-8 md:!flex-row">
				<FavoriteList favoriteList={favoriteList} />
			</div>
		</div>
	)
}