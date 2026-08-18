/** @type {import('tailwindcss').Config} */
export default {
  content: ['./index.html', './src/**/*.{js,jsx,ts,tsx}'],
  theme: {
    extend: {
      fontFamily: {
        sans: ['Inter', 'system-ui', '-apple-system', 'Segoe UI', 'sans-serif'],
        mono: ['"JetBrains Mono"', '"Cascadia Code"', 'Consolas', 'monospace'],
      },
      colors: {
        surface: {
          DEFAULT: '#0d1219',   // page background
          raised: '#131a23',    // card/panel
          elevated: '#1a2330',  // modal, dropdown, popover
          hover: '#212b3a',     // hover wash on raised surfaces
        },
        border: {
          DEFAULT: 'rgba(255,255,255,0.08)',
          strong: 'rgba(255,255,255,0.14)',
        },
        ink: {
          DEFAULT: '#eef1f4',
          soft: '#9aa7b4',
          faint: '#66768a',
        },
        accent: {
          DEFAULT: '#35b7be',
          soft: 'rgba(53,183,190,0.14)',
          text: '#5fd1d7',
        },
        severity: {
          low: '#2f9d5c',
          'low-text': '#5fc98a',
          'low-soft': 'rgba(47,157,92,0.14)',
          medium: '#ad8f1e',
          'medium-text': '#e0b84a',
          'medium-soft': 'rgba(173,143,30,0.14)',
          high: '#c85a2e',
          'high-text': '#e2825a',
          'high-soft': 'rgba(200,90,46,0.14)',
          critical: '#d03b3b',
          'critical-text': '#e8635c',
          'critical-soft': 'rgba(208,59,59,0.14)',
        },
      },
      boxShadow: {
        card: '0 1px 2px rgba(0,0,0,0.24), 0 8px 24px -12px rgba(0,0,0,0.4)',
        elevated: '0 12px 32px -8px rgba(0,0,0,0.55)',
        'ring-accent': '0 0 0 3px rgba(53,183,190,0.25)',
      },
      borderRadius: {
        xl2: '1.125rem',
      },
    },
  },
  plugins: [],
};
