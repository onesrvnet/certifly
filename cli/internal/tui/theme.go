// Package tui is the certifly terminal UI: sign-in, host picker, certificates and settings, and the
// host setup screens.
package tui

import (
	"image/color"

	"charm.land/huh/v2"
	"charm.land/lipgloss/v2"
)

// Theme holds the styles in the certifly brand colours, picked for a light or dark terminal.
type Theme struct {
	IsDark bool

	Brand, Accent, Muted, Fg, Subtle, Success, Warning, Danger, Border, OnBrand color.Color
	// Palette colours host group badges.
	Palette []color.Color

	App, Header, Title, Tab, TabActive, Dim, Strong, Key, Hint, Code, Selected, Row, OK, Warn, Bad, Box, Badge, Nav, NavActive, Section lipgloss.Style
}

// NewTheme builds the styles. The colours follow the web app: brand violet, and the status colours.
func NewTheme(isDark bool) Theme {
	ld := lipgloss.LightDark(isDark)
	t := Theme{
		IsDark:  isDark,
		Brand:   ld(lipgloss.Color("#5b47c9"), lipgloss.Color("#8f7ff0")),
		Muted:   ld(lipgloss.Color("#6b6b76"), lipgloss.Color("#9a9aa6")),
		Fg:      ld(lipgloss.Color("#1c1c22"), lipgloss.Color("#ececf1")),
		Subtle:  ld(lipgloss.Color("#ececf3"), lipgloss.Color("#24232d")),
		Success: ld(lipgloss.Color("#1d7f55"), lipgloss.Color("#4cc38a")),
		Warning: ld(lipgloss.Color("#a35f00"), lipgloss.Color("#f0a742")),
		Danger:  ld(lipgloss.Color("#c23a4b"), lipgloss.Color("#f0707d")),
		Border:  ld(lipgloss.Color("#d6d6e0"), lipgloss.Color("#3a3946")),
		Accent:  ld(lipgloss.Color("#b0459b"), lipgloss.Color("#e58fd6")),
		OnBrand: lipgloss.Color("#ffffff"),
	}
	t.Palette = []color.Color{
		ld(lipgloss.Color("#2c6bc4"), lipgloss.Color("#7aa8f0")),
		ld(lipgloss.Color("#1d7f55"), lipgloss.Color("#5fd0a0")),
		ld(lipgloss.Color("#a35f00"), lipgloss.Color("#f0b35e")),
		ld(lipgloss.Color("#b0459b"), lipgloss.Color("#e58fd6")),
		ld(lipgloss.Color("#0e7f86"), lipgloss.Color("#5fd3d8")),
		ld(lipgloss.Color("#5b47c9"), lipgloss.Color("#a597f5")),
	}
	t.App = lipgloss.NewStyle().Padding(0, 1)
	t.Box = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(t.Border).Padding(0, 1)
	t.Header = lipgloss.NewStyle().Foreground(t.Muted)
	t.Title = lipgloss.NewStyle().Foreground(t.Brand).Bold(true)
	t.Tab = lipgloss.NewStyle().Foreground(t.Muted).Padding(0, 1)
	t.TabActive = lipgloss.NewStyle().Foreground(t.Brand).Bold(true).Padding(0, 1).Underline(true)
	t.Dim = lipgloss.NewStyle().Foreground(t.Muted)
	t.Strong = lipgloss.NewStyle().Foreground(t.Fg).Bold(true)
	t.Key = lipgloss.NewStyle().Foreground(t.Brand).Bold(true)
	t.Hint = lipgloss.NewStyle().Foreground(t.Muted)
	t.Code = lipgloss.NewStyle().Foreground(t.Brand).Bold(true).Padding(0, 2).Border(lipgloss.RoundedBorder()).BorderForeground(t.Brand)
	t.Selected = lipgloss.NewStyle().Background(t.Subtle).Foreground(t.Fg).Bold(true)
	t.NavActive = lipgloss.NewStyle().Background(t.Brand).Foreground(t.OnBrand).Bold(true).Padding(0, 1)
	t.Nav = lipgloss.NewStyle().Foreground(t.Fg).Padding(0, 1)
	t.Section = lipgloss.NewStyle().Foreground(t.Muted).Bold(true)
	t.Row = lipgloss.NewStyle().Foreground(t.Fg)
	t.OK = lipgloss.NewStyle().Foreground(t.Success)
	t.Warn = lipgloss.NewStyle().Foreground(t.Warning)
	t.Bad = lipgloss.NewStyle().Foreground(t.Danger)
	t.Badge = lipgloss.NewStyle().Foreground(t.Brand).Border(lipgloss.RoundedBorder()).BorderForeground(t.Border).Padding(0, 1)
	return t
}

// Form is the huh theme in the same colours.
func (t Theme) Form() huh.Theme {
	return huh.ThemeFunc(func(isDark bool) *huh.Styles {
		s := huh.ThemeBase(isDark)
		th := NewTheme(isDark)
		s.Focused.Base = s.Focused.Base.BorderForeground(th.Brand)
		s.Focused.Title = s.Focused.Title.Foreground(th.Brand).Bold(true)
		s.Focused.Description = s.Focused.Description.Foreground(th.Muted)
		s.Focused.SelectSelector = s.Focused.SelectSelector.Foreground(th.Brand)
		s.Focused.SelectedOption = s.Focused.SelectedOption.Foreground(th.Brand)
		s.Focused.FocusedButton = s.Focused.FocusedButton.Background(th.Brand).Foreground(lipgloss.Color("#ffffff"))
		s.Focused.TextInput.Cursor = s.Focused.TextInput.Cursor.Foreground(th.Brand)
		s.Focused.TextInput.Prompt = s.Focused.TextInput.Prompt.Foreground(th.Brand)
		s.Focused.ErrorMessage = s.Focused.ErrorMessage.Foreground(th.Danger)
		s.Focused.ErrorIndicator = s.Focused.ErrorIndicator.Foreground(th.Danger)
		s.Blurred = s.Focused
		s.Blurred.Base = s.Blurred.Base.BorderForeground(th.Border)
		s.Blurred.Title = s.Blurred.Title.Foreground(th.Muted).Bold(false)
		return s
	})
}
