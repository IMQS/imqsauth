import { createApp } from 'vue';
import App from './App.vue';

// Material Design typography (bundled, so it works fully offline) and the
// shared Material Design foundation (colors, elevation, base component styles).
// 'latin' + 'latin-ext' Unicode subsets are imported (covers accented Latin
// characters common in real names/emails, e.g. é, ñ, ü) without bloating the
// embedded Go binary with glyph ranges this app never needs (cyrillic/greek/etc).
// Without latin-ext, any character outside the bare 'latin' subset (which is
// narrower than it sounds) silently falls back to the system font for just
// those glyphs - which is exactly what caused the logged-in username (an
// email/display name) to appear in a different font than the rest of the UI.
import '@fontsource/roboto/latin-300.css';
import '@fontsource/roboto/latin-400.css';
import '@fontsource/roboto/latin-500.css';
import '@fontsource/roboto/latin-700.css';
import '@fontsource/roboto/latin-ext-300.css';
import '@fontsource/roboto/latin-ext-400.css';
import '@fontsource/roboto/latin-ext-500.css';
import '@fontsource/roboto/latin-ext-700.css';
import './assets/material.css';

createApp(App).mount('#app');

