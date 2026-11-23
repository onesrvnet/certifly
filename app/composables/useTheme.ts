import { createSharedComposable, useColorMode } from '@vueuse/core'

/** Shared colour mode (`light` | `dark` | `auto`), persisted in localStorage. */
export const useTheme = createSharedComposable(() => useColorMode({ storageKey: 'certifly-color-scheme' }))

/** Runs before first paint so SSR pages don't flash the wrong theme. */
export const themeBootScript = `(function(){try{var m=localStorage.getItem('certifly-color-scheme')||'auto';var d=m==='dark'||(m==='auto'&&matchMedia('(prefers-color-scheme: dark)').matches);document.documentElement.classList.toggle('dark',d)}catch(e){}})()`
