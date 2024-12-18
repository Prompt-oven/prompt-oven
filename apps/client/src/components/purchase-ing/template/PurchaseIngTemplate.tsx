"use client"

import { useState } from "react"
import type { PaymentItemType } from "@/types/purchase.ts/purchase-ongoing"
import type methodGroup from "../atom/icon/MethodGroup"
import PurchaseIngTitle from "../atom/PurchaseIngTitle"
import PaymentDetail from "../organism/PaymentDetail"
import PaymentMethod from "../organism/PaymentMethod"
import PaymentOrder from "../organism/PaymentOrder"

interface PurchaseIngTemplateProps {
	paymentList: PaymentItemType[]
}

interface SelectedMethod {
	type: keyof typeof methodGroup // methodGroup 객체의 키 중 하나를 선택할 수 있는 타입
	payment?: string
}

export default function PurchaseIngTemplate({
	paymentList,
}: PurchaseIngTemplateProps) {
	const [selectedMethod, setSelectedMethod] = useState<SelectedMethod>({
		type: "general", // 기본 결제 유형
		payment: undefined, // 선택된 결제 방법
	})

	const totalPrice = paymentList.reduce((sum, item) => {
		return sum + parseInt(item.productPrice)
	}, 0)

	return (
		<div className="mb-12 mt-4 flex flex-col gap-6">
			<PurchaseIngTitle />

			<div className="mx-6 flex flex-col justify-between gap-8 md:!flex-row">
				<div className="flex w-full flex-col gap-8 md:w-[700px]">
					<PaymentMethod
						method={selectedMethod}
						setMethod={setSelectedMethod}
					/>
					<PaymentDetail paymentList={paymentList} totalPrice={totalPrice} />
				</div>

				<PaymentOrder
					method={selectedMethod}
					paymentList={paymentList}
					totalPrice={totalPrice}
				/>
			</div>
		</div>
	)
}
