package org.derooms.app.ui.theme

import androidx.compose.material3.MaterialTheme
import androidx.compose.material3.Typography
import androidx.compose.material3.darkColorScheme
import androidx.compose.runtime.Composable
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.TextStyle
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.sp

/** Forest / moss product palette — calm messenger, not neon “crypto”. */
object DeroomsColors {
    val Moss = Color(0xFF7CBA3D)
    val MossDim = Color(0xFF5A8F2C)
    val Ink = Color(0xFF0B1210)
    val InkElevated = Color(0xFF141C18)
    val Panel = Color(0xFF1A2420)
    val PanelSoft = Color(0xFF222E28)
    val Cream = Color(0xFFE6EDE4)
    val CreamMuted = Color(0xFFA8B5A6)
    val BubbleOut = Color(0xFF2A4A32)
    val BubbleIn = Color(0xFF1E2822)
    val Danger = Color(0xFFC45C4A)
    val Line = Color(0xFF2C3830)
}

private val DarkScheme = darkColorScheme(
    primary = DeroomsColors.Moss,
    onPrimary = DeroomsColors.Ink,
    primaryContainer = DeroomsColors.MossDim,
    onPrimaryContainer = DeroomsColors.Cream,
    secondary = DeroomsColors.CreamMuted,
    onSecondary = DeroomsColors.Ink,
    background = DeroomsColors.Ink,
    onBackground = DeroomsColors.Cream,
    surface = DeroomsColors.InkElevated,
    onSurface = DeroomsColors.Cream,
    surfaceVariant = DeroomsColors.Panel,
    onSurfaceVariant = DeroomsColors.CreamMuted,
    outline = DeroomsColors.Line,
    error = DeroomsColors.Danger,
)

private val AppTypography = Typography(
    displayLarge = TextStyle(
        fontFamily = FontFamily.Serif,
        fontWeight = FontWeight.Bold,
        fontSize = 40.sp,
        lineHeight = 44.sp,
        letterSpacing = (-0.5).sp,
    ),
    headlineMedium = TextStyle(
        fontFamily = FontFamily.Serif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 24.sp,
        lineHeight = 30.sp,
    ),
    titleLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 20.sp,
    ),
    titleMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 16.sp,
    ),
    bodyLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 16.sp,
        lineHeight = 22.sp,
    ),
    bodyMedium = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 14.sp,
        lineHeight = 20.sp,
    ),
    bodySmall = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.Normal,
        fontSize = 12.sp,
        lineHeight = 16.sp,
        color = DeroomsColors.CreamMuted,
    ),
    labelLarge = TextStyle(
        fontFamily = FontFamily.SansSerif,
        fontWeight = FontWeight.SemiBold,
        fontSize = 14.sp,
    ),
)

@Composable
fun DeroomsTheme(
    content: @Composable () -> Unit,
) {
    MaterialTheme(
        colorScheme = DarkScheme,
        typography = AppTypography,
        content = content,
    )
}
