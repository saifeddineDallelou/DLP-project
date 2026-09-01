import '@testing-library/jest-dom/vitest';
import { cleanup } from '@testing-library/react';
import { afterEach, vi } from 'vitest';

// Unmount between tests. Without this, a component from an earlier test is
// still in the DOM and queries match the wrong element -- which produces
// failures that look like component bugs and are not.
afterEach(() => {
  cleanup();
  vi.clearAllMocks();
});

// jsdom implements neither of these, and Recharts' ResponsiveContainer calls
// both. Without the stubs every page rendering a chart throws on mount.
global.ResizeObserver = class {
  observe() {}
  unobserve() {}
  disconnect() {}
};

if (!window.matchMedia) {
  window.matchMedia = (query) => ({
    matches: false,
    media: query,
    onchange: null,
    addEventListener() {},
    removeEventListener() {},
    dispatchEvent() { return false; },
  });
}
