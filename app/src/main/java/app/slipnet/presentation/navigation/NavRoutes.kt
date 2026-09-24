package app.slipnet.presentation.navigation

sealed class NavRoutes(val route: String) {
    data object Home : NavRoutes("home")
    data object AddProfile : NavRoutes("add_profile/{tunnelType}") {
        fun createRoute(tunnelType: String) = "add_profile/$tunnelType"
    }
    data object EditProfile : NavRoutes("edit_profile/{profileId}") {
        fun createRoute(profileId: Long) = "edit_profile/$profileId"
    }
    data object Settings : NavRoutes("settings")
    data object AppSelector : NavRoutes("app_selector")
    data object AddChain : NavRoutes("add_chain")
    data object EditChain : NavRoutes("edit_chain/{chainId}") {
        fun createRoute(chainId: Long) = "edit_chain/$chainId"
    }
}
