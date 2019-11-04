<template>
	<div id="app">
		<div id="app-sub">
			<login-page />
		</div>
	</div>
</template>

<style lang="less">
#app {
	height: 100%;
	width: 100%;
}

#app-sub {
	height: 100%;
	width: 100%;
}

#app {
	height: 100%;
}
</style>

<script lang="ts">
import Vue from 'vue';
import { Component } from "vue-property-decorator";
import LoginPage from 'src/components/auth/LoginPage/login-page';
import { loadApplicationThemeFromLocalStorage, themes, setApplicationThemes } from 'lib/theme/application-theme';
import { isLoggedIn } from 'lib/auth';
import { getHashQueryParamFromURL } from 'lib/base/uri';
import { redirectToQueryParam } from './base/utils';

@Component({
	components: { 'login-page': LoginPage }
})
export default class App extends Vue {
	currentTab = "IN";

	beforeCreate() {
		if (isLoggedIn()) {
			redirectToQueryParam();
		}
	}

	created() {
		let t = {
			"default": {
				doImport: () => {
					return import("src/themes/default");
				}
			},
			"classic": {
				// local-storage value for the default theme is set to "classic" if a user explicitly picks the default option,
				// otherwise it will automatically be set to "default".
				doImport: () => {
					return import("src/themes/default");
				}
			},
			"light": {
				doImport: () => {
					return import("src/themes/light");
				}
			},
			"dark": {
				doImport: () => {
					return import("src/themes/dark");
				}
			}
		};
		setApplicationThemes(t);

		loadApplicationThemeFromLocalStorage(() => {
			console.log("\n\n\nLoaded");
		});
	}
}
</script>
