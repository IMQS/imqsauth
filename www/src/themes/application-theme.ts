import { userStorage } from 'lib/storage/user_storage';
import { LocalStorageKeys } from 'lib/storage/local_storage';
import { log } from 'lib/log';

/*
* Themes are managed by delay-loading seperate CSS files that override previously defined CSS classes
* CSS has a property that any classes loaded later that have the same name will override previously loaded classes
* Within a class you don't need to override styles that stay the same, only theme-specific styles.
* For instance, if you only want to override the color for this style:
*     .someClass {
* 	      color: red;
*         font-size: 14px;
*     }
* then you would add a themed class with just that one style:
*     .someClass {
*         color: blue;
*     }
* The CSS of the classes will be merged and the themed class will "win" when it comes to the `color` style
* because it is loaded later.
*
* When we switch themes we loop through all previously loaded themes' CSS (stored in `document.styleSheets`)
* and deactivate the styles other than the styles for the currently selected theme. This might seem a bit messy,
* but works quite well in practise.
*/


type idxTuple = [number, number]; // tuple of start and end index for custom styles

const defaultThemeName = "default";

export interface IApplicationTheme {
	doImport: () => Promise<any>;
	startIdx?: number;
	endIdx?: number;
	loaded?: boolean;
}

// At some point we'll add a client-specific themes driven from config.
// Then we'll turn this `const` into a method that returns client-specific themes.
// Note that the import paths here have to be hardcoded at compile-time (a limitation of webpack's delay-loading mechanism)
/* tslint:disable */
const themes: { [key: string]: IApplicationTheme } = {
	"default": {
		doImport: () => {
			return import("../themes/default");
		}
	},
	"classic": {
		// local-storage value for the default theme is set to "classic" if a user explicitly picks the default option,
		// otherwise it will automatically be set to "default".
		doImport: () => {
			return import("../themes/default");
		}
	},
	"light": {
		doImport: () => {
			return import("../themes/light");
		}
	},
	"dark": {
		doImport: () => {
			return import("../themes/dark");
		}
	}
};
/* tslint:enable */

export function loadApplicationThemeFromLocalStorage(onDone: () => void) {
	const themeNameQuoted = localStorage.getItem(LocalStorageKeys.ApplicationTheme);
	if (!themeNameQuoted) {
		onDone();
		return;
	}
	let themeName = defaultThemeName;
	try {
		themeName = JSON.parse(themeNameQuoted);
	} catch (err) {
		// do nothing, just default to default theme
	}
	activateApplicationTheme(themeName, onDone);
}

function switchTheme(themeName: string, onDone: () => void) {
	for (let name in themes) {
		if (!themes[name].loaded && themes[name].startIdx && themes[name].endIdx) continue;
		const disabled = (name !== themeName); // disable all themes except the current theme
		// for (let i = themes[name].startIdx || 0; i <= (themes[name].endIdx || 0); i++)
		// 	document.styleSheets[i].disabled = disabled;
	}
	if (userStorage) { // userStorage may not be initialised yet
		userStorage.setItem(LocalStorageKeys.ApplicationTheme, themeName);
	} else {
		localStorage.setItem(LocalStorageKeys.ApplicationTheme, JSON.stringify(themeName)); // need to stringify because userStorage does this as well
	}

	if (onDone)
		onDone();
}

export function activateApplicationTheme(themeName: string, onDone = () => { }) {
	const lastStyleIdx = document.styleSheets.length;
	let theme = themes[themeName];
	if (!theme) {
		// fall back to default
		themeName = defaultThemeName;
		theme = themes[themeName];
	}
	if (!theme.loaded) {
		theme.doImport().then(cssModule => {
			theme.loaded = true;
			theme.startIdx = lastStyleIdx;
			theme.endIdx = document.styleSheets.length - 1;

			switchTheme(themeName, onDone);
		}).catch(error => {
			log.logErr(`Error loading theme: ${error}`);
			onDone();
		});
	} else {
		switchTheme(themeName, onDone);
	}
}
