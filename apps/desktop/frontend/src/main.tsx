/**
 * Frontend entry point.
 *
 * The root renders `App` and nothing else: no router, no providers, no global CSS imports
 * beyond the one stylesheet. State lives in the engine store, which mirrors the Rust engine.
 */

import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { App } from '@/app/App';
import '@/app/index.css';

const container = document.getElementById('root');
if (!container) {
  throw new Error('Sentinel could not find its root element; the window markup is broken.');
}

createRoot(container).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
