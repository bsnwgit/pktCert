/** @type {import('tailwindcss').Config} */
//
// ── FOUNDATION THEME ─────────────────────────────────────────────────────────
// Shared across every pkt* app. The suite is restyled by remapping Tailwind's
// palette rather than rewriting every className, so existing utilities keep
// their semantic meaning:
//
//   gray-*   → the warm near-black field and its ink scale
//   blue-*   → gold (the primary / active / system channel)
//   cyan / sky / teal → ice blue (data flux, the secondary channel)
//   red / yellow / amber → alarm + warning, the only high-chroma colours
//
// Two deliberate separations:
//
//   1. borderColor and divideColor are overridden independently of colors.
//      Backgrounds need to stay near-black while every rule, divider and
//      panel edge reads as a visible warm hairline. Tying them to one scale
//      forces a choice between invisible dividers and washed-out panels.
//
//   2. Radii are flattened to 0 (rounded-full excepted, since status dots and
//      avatars depend on it) — hairline geometry, not soft cards.
// ─────────────────────────────────────────────────────────────────────────────

// Warm ink scale. 500 is the workhorse for secondary text and is kept bright
// enough to stay comfortably legible on the near-black field.
const ink = {
  50:  '#faf8f2', 100: '#f2eee5', 200: '#e9e4d8', 300: '#dcd6c9',
  400: '#c7c0b1', 500: '#a9a294', 600: '#5c6470', 700: '#39414c',
  800: '#10141b', 900: '#080b11', 950: '#04060a',
}

const gold = {
  50:  '#fdf8ec', 100: '#fbf3e0', 200: '#f8ebcc', 300: '#f5e2b6',
  400: '#e9cd95', 500: '#d8b46e', 600: '#b58f47', 700: '#7d6130',
  800: '#4a3a1c', 900: '#2f2512', 950: '#1a1206',
}

const ice = {
  50:  '#eefafd', 100: '#d8f2f8', 200: '#bde9f2', 300: '#a5e0ed',
  400: '#8ad8ea', 500: '#63c3d8', 600: '#469fb4', 700: '#2f7284',
  800: '#1d4653', 900: '#122a33', 950: '#08151a',
}

const alarm = {
  50:  '#fff0ee', 100: '#ffdcd8', 200: '#ffc9c3', 300: '#ffb0a8',
  400: '#ff9086', 500: '#ff6b5e', 600: '#e04a3c', 700: '#a8342a',
  800: '#6b1f1a', 900: '#4a1512', 950: '#2a0d0a',
}

const warn = {
  50:  '#fdf6e6', 100: '#faebc9', 200: '#f9dfa8', 300: '#f8d590',
  400: '#f3c265', 500: '#e5aa3d', 600: '#bd8626', 700: '#855d1a',
  800: '#4d340c', 900: '#3a2a08', 950: '#1f1604',
}

const live = {
  50:  '#eefaf3', 100: '#d3f4e2', 200: '#b4edcf', 300: '#9aeabd',
  400: '#7ee0a8', 500: '#52cc8e', 600: '#37a670', 700: '#24754e',
  800: '#12422c', 900: '#0d2a1c', 950: '#061710',
}

const amethyst = {
  50:  '#f4f1fb', 100: '#e7e1f6', 200: '#d3c9ee', 300: '#c4b7e9',
  400: '#b0a0dd', 500: '#9784cb', 600: '#7867ad', 700: '#544777',
  800: '#32294e', 900: '#241c3a', 950: '#150f22',
}

// Border + divider hairlines: warm gold at graded alpha. Named by the same
// numeric keys the apps already use, so `border-gray-800` etc. keep working
// and simply become visible.
const hairline = {
  50:  'rgba(245,226,182,.62)',
  100: 'rgba(245,226,182,.54)',
  200: 'rgba(233,205,149,.48)',
  300: 'rgba(216,180,110,.44)',
  400: 'rgba(216,180,110,.40)',
  500: 'rgba(216,180,110,.36)',
  600: 'rgba(216,180,110,.32)',
  700: 'rgba(216,180,110,.28)',
  800: 'rgba(216,180,110,.22)',
  900: 'rgba(216,180,110,.16)',
  950: 'rgba(216,180,110,.12)',
}

export default {
  content: ['./index.html', './src/**/*.{ts,tsx}'],
  darkMode: 'class',
  theme: {
    extend: {
      colors: {
        // Warm off-white ink — pure #fff never appears on these screens.
        white: '#f5f1e8',

        gray: ink,
        slate: ink,
        zinc: ink,
        neutral: ink,
        stone: ink,

        // gold: primary / active / system
        blue: gold,
        indigo: gold,

        // ice: secondary data channel
        cyan: ice,
        sky: ice,
        teal: ice,

        // status
        red: alarm,
        rose: alarm,
        orange: { ...warn, 400: '#f5a072', 500: '#e88450', 600: '#c26635' },
        yellow: warn,
        amber: warn,
        green: live,
        emerald: live,
        lime: live,

        // rare accents kept in-family
        purple: amethyst,
        violet: amethyst,
        fuchsia: amethyst,
        pink: amethyst,

        // named tokens for new markup
        gold, ice, alarm, warn, live,
      },

      // Dividers and edges read as warm hairlines regardless of the
      // background token the markup happens to name.
      borderColor: {
        DEFAULT: 'rgba(216,180,110,.28)',
        gray: hairline, slate: hairline, zinc: hairline,
        neutral: hairline, stone: hairline,
      },
      divideColor: {
        DEFAULT: 'rgba(216,180,110,.24)',
        gray: hairline, slate: hairline, zinc: hairline,
        neutral: hairline, stone: hairline,
      },
      ringColor: {
        DEFAULT: 'rgba(216,180,110,.45)',
      },

      fontFamily: {
        sans: ['"Helvetica Neue"', 'Inter', 'system-ui', '-apple-system', 'sans-serif'],
        mono: ['ui-monospace', '"SF Mono"', 'SFMono-Regular', 'Menlo', '"Roboto Mono"', 'monospace'],
      },

      letterSpacing: {
        micro: '0.3em',
        instrument: '0.22em',
      },
    },

    borderRadius: {
      none: '0', sm: '0', DEFAULT: '0', md: '0', lg: '0',
      xl: '0', '2xl': '0', '3xl': '0', full: '9999px',
    },
  },
  plugins: [],
}
