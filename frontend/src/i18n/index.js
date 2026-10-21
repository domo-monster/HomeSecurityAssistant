// UI and Settings-form translations, loaded on demand.
// English text is the inline fallback of each _t() call, so English needs no
// file. Other languages are fetched once from content-hashed JSON files that
// sit next to the bundle (see build.mjs).

/* global __HSA_LOCALE_FILES__ */
const LOCALE_FILES = __HSA_LOCALE_FILES__;

// Filled in place: modules that imported these objects see loaded languages.
export const UI_I18N = {};
export const SETTINGS_SCHEMA_I18N = {};

const pending = {};

/** Load a locale's translations; resolves once they are available (or failed). */
export function loadLocale(locale) {
  if (!LOCALE_FILES[locale] || UI_I18N[locale]) return Promise.resolve();
  if (!pending[locale]) {
    pending[locale] = fetch(new URL(LOCALE_FILES[locale], import.meta.url))
      .then((resp) => (resp.ok ? resp.json() : Promise.reject(new Error(`HTTP ${resp.status}`))))
      .then((data) => {
        UI_I18N[locale] = data.ui || {};
        SETTINGS_SCHEMA_I18N[locale] = data.settings || {};
      })
      .catch((err) => {
        // Fall back to English rather than failing the panel
        console.warn(`[HomeSec] could not load ${locale} translations:`, err);
        delete pending[locale];
      });
  }
  return pending[locale];
}
