import type { ForwardRefExoticComponent, RefAttributes } from "react"
import type { LucideProps } from "@repo/ui/lucide"
import {
	Cookie,
	Hammer,
	Heart,
	House,
	LayoutDashboard,
	LogIn,
	Package,
	Settings,
	ShoppingBag,
	ShoppingCart,
	SquareTerminal,
	Store,
	TrophyIcon,
	User,
	UserPlus,
} from "@repo/ui/lucide"
import type { UserAuthType } from "@/lib/userAuth.ts"

export type MenuIconType = ForwardRefExoticComponent<
	Omit<LucideProps, "ref"> & RefAttributes<SVGSVGElement>
>

export type NavQueryType = Record<string, string>
export interface BaseMenuItemType {
	icon: MenuIconType
	label: string
	href: string
	query: NavQueryType
}
export interface SubMenuItemType extends Omit<BaseMenuItemType, "icon"> {
	icon?: ForwardRefExoticComponent<
		Omit<LucideProps, "ref"> & RefAttributes<SVGSVGElement>
	>
}

export interface MenuNavItemType extends BaseMenuItemType {
	subMenu?: SubMenuItemType[]
}

export interface HeaderNavType
	extends Omit<BaseMenuItemType, "query" | "icon"> {
	icon?: MenuIconType
}

// ----------------- Avatar Navs -----------------

export const commonNavs: MenuNavItemType[] = [
	{
		icon: House,
		label: "Home",
		href: "/",
		query: {},
	},
	{
		icon: SquareTerminal,
		label: "Prompts",
		href: "/prompts",
		query: {},
	},
	{
		icon: TrophyIcon,
		label: "Best",
		href: "/best",
		query: {},
	},
]

export const sellerNavs: MenuNavItemType[] = [
	{
		icon: LayoutDashboard,
		label: "Overview",
		href: "/account",
		query: { view: "overview" },
	},
	{
		icon: Package,
		label: "Product",
		href: "/account",
		query: { view: "product-list" },
	},
	{
		icon: User,
		label: "Profile",
		href: "/account",
		query: { view: "profile" },
	},
	{
		icon: Heart,
		label: "Favorites",
		href: "/account",
		query: { view: "favorites" },
	},
	{
		icon: ShoppingCart,
		label: "Cart",
		href: "/account",
		query: { view: "cart" },
	},
	{
		icon: ShoppingBag,
		label: "Purchases",
		href: "/account",
		query: { view: "purchase-completed" },
		subMenu: [
			{
				label: "Ongoing",
				href: "/account",
				query: { view: "purchase-ongoing" },
			},
			{
				label: "Completed",
				href: "/account",
				query: { view: "purchase-completed" },
			},
		],
	},
	{
		icon: Hammer,
		label: "Commission",
		href: "/account",
		query: { view: "commission" },
	},
	{
		icon: Cookie,
		label: "Cookie",
		href: "/account",
		query: { view: "cookie" },
	},
	...commonNavs,
	{
		icon: Settings,
		label: "Settings",
		href: "/account",
		query: { view: "settings" },
	},
]

export const userNavs: MenuNavItemType[] = [
	{
		label: "To Be Seller",
		href: "/seller/registration",
		query: {},
		icon: Store,
	},
	{
		icon: User,
		label: "Profile",
		href: "/account",
		query: { view: "profile" },
	},
	{
		icon: Heart,
		label: "Favorites",
		href: "/account",
		query: { view: "favorites" },
	},
	{
		icon: ShoppingCart,
		label: "Cart",
		href: "/account",
		query: { view: "cart" },
	},
	{
		icon: ShoppingBag,
		label: "Purchases",
		href: "/account",
		query: { view: "purchase-completed" },
		subMenu: [
			{
				label: "Ongoing",
				href: "/account",
				query: { view: "purchase-ongoing" },
			},
			{
				label: "Completed",
				href: "/account",
				query: { view: "purchase-completed" },
			},
		],
	},
	{
		icon: Hammer,
		label: "Commission",
		href: "/account",
		query: { view: "buyer-commission" },
	},
	{
		icon: Cookie,
		label: "Cookie",
		href: "/account",
		query: { view: "cookie" },
	},
	...commonNavs,
	{
		icon: Settings,
		label: "Settings",
		href: "/account",
		query: { view: "settings" },
	},
]

export const guestNavs: MenuNavItemType[] = [
	{
		icon: LogIn,
		label: "Sign In",
		href: "/sign-in",
		query: {},
	},
	{
		icon: UserPlus,
		label: "Sign Up",
		href: "/sign-up",
		query: {},
	},
	...commonNavs,
]

// ----------------- SideBar Menu Navs -----------------

export const getUserAuthNavitems = (userAuth: UserAuthType) => {
	let menuItems!: MenuNavItemType[]
	if (userAuth === "seller" || userAuth === "admin") {
		menuItems = sellerNavs
	} else if (userAuth === "member") {
		menuItems = userNavs
	} else {
		menuItems = guestNavs
	}
	return menuItems
}

