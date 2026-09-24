package app.slipnet.presentation.navigation

import androidx.compose.animation.EnterTransition
import androidx.compose.animation.ExitTransition
import androidx.compose.runtime.Composable
import androidx.compose.ui.Modifier
import androidx.navigation.NavHostController
import androidx.navigation.NavType
import androidx.navigation.compose.NavHost
import androidx.navigation.compose.composable
import androidx.navigation.navArgument
import app.slipnet.presentation.chain.EditChainScreen
import app.slipnet.presentation.main.MainScreen
import app.slipnet.presentation.profiles.EditProfileScreen
import app.slipnet.presentation.settings.AppSelectorScreen
import app.slipnet.presentation.settings.SettingsScreen

@Composable
fun NavGraph(
    navController: NavHostController,
    modifier: Modifier = Modifier
) {
    NavHost(
        navController = navController,
        startDestination = NavRoutes.Home.route,
        modifier = modifier,
        enterTransition = { EnterTransition.None },
        exitTransition = { ExitTransition.None },
        popEnterTransition = { EnterTransition.None },
        popExitTransition = { ExitTransition.None }
    ) {
        composable(NavRoutes.Home.route) {
            MainScreen(
                onNavigateToAddProfile = { tunnelType ->
                    navController.navigate(NavRoutes.AddProfile.createRoute(tunnelType))
                },
                onNavigateToEditProfile = { profileId ->
                    navController.navigate(NavRoutes.EditProfile.createRoute(profileId))
                },
                onNavigateToSettings = {
                    navController.navigate(NavRoutes.Settings.route)
                },
                onNavigateToAddChain = {
                    navController.navigate(NavRoutes.AddChain.route)
                },
                onNavigateToEditChain = { chainId ->
                    navController.navigate(NavRoutes.EditChain.createRoute(chainId))
                }
            )
        }

        composable(NavRoutes.AddChain.route) {
            EditChainScreen(
                onNavigateBack = { navController.popBackStack() }
            )
        }

        composable(
            route = NavRoutes.EditChain.route,
            arguments = listOf(
                navArgument("chainId") { type = NavType.LongType }
            )
        ) {
            EditChainScreen(
                onNavigateBack = { navController.popBackStack() }
            )
        }

        composable(
            route = NavRoutes.AddProfile.route,
            arguments = listOf(
                navArgument("tunnelType") { type = NavType.StringType }
            )
        ) {
            EditProfileScreen(
                profileId = null,
                onNavigateBack = {
                    navController.popBackStack()
                }
            )
        }

        composable(
            route = NavRoutes.EditProfile.route,
            arguments = listOf(
                navArgument("profileId") { type = NavType.LongType }
            )
        ) { backStackEntry ->
            val profileId = backStackEntry.arguments?.getLong("profileId")

            EditProfileScreen(
                profileId = profileId,
                onNavigateBack = {
                    navController.popBackStack()
                }
            )
        }

        composable(NavRoutes.Settings.route) {
            SettingsScreen(
                onNavigateBack = {
                    navController.popBackStack()
                },
                onNavigateToAppSelector = {
                    navController.navigate(NavRoutes.AppSelector.route)
                }
            )
        }

        composable(NavRoutes.AppSelector.route) {
            AppSelectorScreen(
                onNavigateBack = {
                    navController.popBackStack()
                }
            )
        }
    }
}
