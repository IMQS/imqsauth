// The Vue build version to load with the `import` command
// (runtime-only or standalone) has been set in webpack.base.conf with an alias.
import Vue from 'vue';
import 'whatwg-fetch';
import 'es6-promise/auto';
import './temp-polyfills';
import { WSListener } from 'lib/wslistener/wslistener';
import { I18n } from 'lib/base/i18n/i18n';
import { UserStorage } from 'lib/storage/user_storage';
import Router from 'vue-router';
import App from 'src/app.vue';
import Element from "element-ui";
import locale from 'element-ui/lib/locale/lang/en';
Vue.use(Element, { locale });
import vSelect from "vue-select";
Vue.component("v-select", vSelect);
import { Loading } from 'element-ui';
Loading.install(Vue);

import "leaflet/dist/leaflet.css";
import 'leaflet.locatecontrol';
import 'proj4leaflet';
import "element-ui/lib/theme-chalk/index.css";
import "lib/css/lib-styles";
import "lib/css/lib-styles-third-party";

Vue.use(Router);

// Allow debugging with "Vue Devtool" and "Vue Performance" Chrome plugins.
Vue.config.devtools = true;
Vue.config.performance = true;

Vue.config.productionTip = false;

WSListener.initWSListener();
I18n.initI18n();
UserStorage.initUserStorage();

const router = new Router({
	base: '/auth/',
	mode: 'history',
	routes: [
		{
			path: '/',
			component: App,
		},
		{
			path: '/foo',
			component: App
		}
	]
});

/* eslint-disable no-new */
new Vue({
	el: '#app',
	router,
	template: '<router-view></router-view>'
});
