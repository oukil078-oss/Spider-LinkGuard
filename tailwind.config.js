/** @type {import('tailwindcss').Config} */
export default {
  content: [
    "./index.html",
    "./src/**/*.{js,ts,jsx,tsx}",
  ],
  theme: {
    extend: {
      colors: {
        slate: {
          950: '#070b13',
          900: '#0b101b',
          850: '#0f1624',
          800: '#1e293b',
          750: '#26344d',
        },
        spider: {
          base: '#070b13',
          card: '#0b101b',
          cardHover: '#0f172a',
          border: '#1e293b',
          accent: '#38bdf8', // sky blue
          warning: '#f59e0b', // amber
          danger: '#ef4444', // red
          critical: '#dc2626', // deep red
          safe: '#10b981', // emerald
          purple: '#a855f7',
        }
      },
      fontFamily: {
        mono: ['JetBrains Mono', 'Fira Code', 'ui-monospace', 'SFMono-Regular', 'Menlo', 'Monaco', 'Consolas', 'monospace'],
        sans: ['Inter', '-apple-system', 'BlinkMacSystemFont', 'Segoe UI', 'Roboto', 'sans-serif'],
      }
    },
  },
  plugins: [],
}
