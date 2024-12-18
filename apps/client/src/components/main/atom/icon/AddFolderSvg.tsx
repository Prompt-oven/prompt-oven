import React, { type SVGProps } from "react"

interface AddFolderProps extends SVGProps<SVGSVGElement> {
	width?: string | number
	height?: string | number
}

function AddFolderSvg({
	width = "50",
	height = "50",
	...props
}: AddFolderProps) {
	return (
		<svg
			width={width}
			height={height}
			viewBox="0 0 50 50"
			fill="none"
			xmlns="http://www.w3.org/2000/svg"
			{...props}>
			<path
				d="M43.75 9.375H26.9434L22.1387 4.95605C20.9668 3.7832 19.3848 3.125 17.7246 3.125H6.25C2.79883 3.125 0 5.92383 0 9.375V40.625C0 44.0762 2.79883 46.875 6.25 46.875H43.75C47.2012 46.875 50 44.0762 50 40.625V15.625C50 12.1777 47.1973 9.375 43.75 9.375ZM45.3125 40.625C45.3125 41.4867 44.6113 42.1875 43.75 42.1875H6.25C5.38867 42.1875 4.6875 41.4867 4.6875 40.625V9.375C4.6875 8.51328 5.38867 7.8125 6.25 7.8125H17.7246C18.1419 7.8125 18.5341 7.975 18.8291 8.27031L25 14.0625H43.75C44.6113 14.0625 45.3125 14.7633 45.3125 15.625V40.625ZM32.8125 25.7812H27.3438V20.2246C27.2559 19.0137 26.2988 17.9688 25 17.9688C23.7012 17.9688 22.6562 19.0137 22.6562 20.2246V25.7812H17.0996C15.8887 25.7812 14.8438 26.8262 14.8438 28.125C14.8438 29.4199 15.8916 30.3809 17.0996 30.3809H22.5684V35.8496C22.6562 37.2363 23.7012 38.2812 25 38.2812C26.2949 38.2812 27.2559 37.2324 27.2559 36.0254V30.3809H32.7246C34.1113 30.3809 35.1562 29.4238 35.1562 28.125C35.1562 26.8262 34.1113 25.7812 32.8125 25.7812Z"
				fill="url(#paint0_linear_351_4550)"
			/>
			<defs>
				<linearGradient
					id="paint0_linear_351_4550"
					x1="-3.36134"
					y1="-15.25"
					x2="45.5389"
					y2="-6.90289"
					gradientUnits="userSpaceOnUse">
					<stop stopColor="#FCB808" />
					<stop offset="1" stopColor="#F9075E" />
				</linearGradient>
			</defs>
		</svg>
	)
}

export default AddFolderSvg
