/** @type {import('tailwindcss').Config} */
module.exports = {
  content: [
    './pages/**/*.{js,ts,jsx,tsx,mdx}',
    './components/**/*.{js,ts,jsx,tsx,mdx}',
    './app/**/*.{js,ts,jsx,tsx,mdx}',
  ],
  theme: {
    extend: {
      colors: {
        // Classic Silk Road Dark Theme
        'silk-black': '#0a0a0a',
        'silk-dark': '#1a1a1a',
        'silk-gray': '#2a2a2a',
        'silk-light': '#3a3a3a',
        'silk-accent': '#8b5cf6',
        'silk-purple': '#7c3aed',
        'silk-gold': '#f59e0b',
        'silk-warning': '#ef4444',
        'silk-success': '#10b981',
        'silk-text': '#e5e5e5',
        'silk-muted': '#9ca3af',
      },
      fontFamily: {
        'mono': ['Source Code Pro', 'Monaco', 'Menlo', 'Ubuntu Mono', 'monospace'],
        'sans': ['Inter', 'system-ui', 'sans-serif'],
      },
      backgroundImage: {
        'silk-gradient': 'linear-gradient(135deg, #0a0a0a 0%, #1a1a1a 50%, #2a2a2a 100%)',
        'silk-card': 'linear-gradient(145deg, #1a1a1a 0%, #2a2a2a 100%)',
      },
      boxShadow: {
        'silk': '0 8px 32px rgba(0, 0, 0, 0.5)',
        'silk-hover': '0 12px 48px rgba(139, 92, 246, 0.3)',
      },
      animation: {
        'fade-in': 'fadeIn 0.5s ease-in-out',
        'slide-up': 'slideUp 0.3s ease-out',
        'pulse-slow': 'pulse 3s cubic-bezier(0.4, 0, 0.6, 1) infinite',
      },
      keyframes: {
        fadeIn: {
          '0%': { opacity: '0' },
          '100%': { opacity: '1' },
        },
        slideUp: {
          '0%': { transform: 'translateY(20px)', opacity: '0' },
          '100%': { transform: 'translateY(0)', opacity: '1' },
        },
      },
    },
  },
  plugins: [],
}
