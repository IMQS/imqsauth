import Vue from "vue";
import * as auth from '@imqs/auth';
import { showNotification } from "@imqs/components/Dialog";
import { tt } from '@imqs/i18n';
import { ajaxJsonGET } from "@imqs/base";
import { windowDimensions } from "@imqs/root/gui";
import { contentPaneID, resize, setSelected, setup } from "../widget/tabs";
import { $id } from "../js-base/utils";
import { WidgetBase } from "../widget/widget-base";
import { AuthUserList } from "../auth/authuserlist";
import { AuthGroupList } from "../auth/authgrouplist";
import { GUI_NAV_HEIGHT } from "../energy/energy-defs";
import { userStorage, LocalStorageKeys } from "@imqs/storage";
import { URLKey } from "../js-base/uri";
import { clientConfig } from '../imqs-client-config';
import UserProfileAuditTrail from "../components/auth/AuditTrail/UserProfileAuditTrail.vue";
import { Module } from "./module";
import { DropdownList } from "./dropdown";
import { Item } from "./navbar";
// Permission administration page

export interface IModuleType {
	id: string;
	value: string;
}

export class NavItemAuth extends DropdownList {

	static usersActive = 0; // these could probably be moved to a ENUM but they work exactly the same like this and they are not used anywhere else
	static usersInActive = 1;
	static usersAll = 2;
	static usersDeleted = 3;

	private userControl: Users;
	private groupControl: Groups;
	private auditTrailControl: AuditTrailControl;

	constructor(parentItem: Item) {
		super(parentItem.navBar, parentItem, "User Management", "UserManagement", "icons-admin", URLKey.Auth.toString(), undefined, undefined, true);
		this.hidden = true;
		this.userControl = new Users(contentPaneID("auth-tabs", "users"));
		this.groupControl = new Groups(contentPaneID("auth-tabs", "groups"));
		if (clientConfig.isFeatureActive("user-audit-trail")) {
			this.auditTrailControl = new AuditTrailControl(contentPaneID("auth-tabs", "audit-trail"));
		}
	}

	// Do not refresh the whole auth page on resize,
	// rather just update the dimensions of important elements
	resize() {
		this.userControl.resize();
		this.groupControl.resize();
	}

	drawContent() {
		this.addDom();
		this.userControl.addDOM();
		this.groupControl.addDOM();
	}

	private addDom() {
		// clear the content container
		this.navBar.contentDiv.empty();

		this.navBar.contentDiv.append(
			`<div id="auth-tabs" style="height:100%; width:100%;"></div>`
		);
		const tabNames = ["users", "groups"];
		const tabTitles = [tt("Users"), tt("Groups")];

		if (clientConfig.isFeatureActive("user-audit-trail")) {
			tabNames.push("audit-trail");
			tabTitles.push(tt("Audit Trail"));
		}

		setup("auth-tabs", tabNames, tabTitles, true);

		setSelected("auth-tabs", "users");

		// slickgrid does not size correctly on a div that is not in the active viewport - so we render on first click
		$id(`auth-tabs-btn-groups`).click(() => {
			this.groupControl.resize();
		});

		$id(`auth-tabs-btn-users`).click(() => {
			this.userControl.resize();
		});

		if (clientConfig.isFeatureActive("user-audit-trail")) {
			$id(`auth-tabs-btn-audit-trail`).click(() => {
				this.auditTrailControl.addDOM();
				this.auditTrailControl.resize();
			});
		}
	}
}

export class Users extends WidgetBase {
	private isUserLoaded: boolean;
	private users: auth.User[] = [];
	private groups: auth.Group[] = [];
	private authModel: auth.Model;
	private availableModules: IModuleType[];
	private adStatus: number;
	private authUserList: AuthUserList;
	private selectedUser: auth.User;
	private filterUser: number;

	constructor(rootID: string) {
		super(rootID);
		this.selectedUser = userStorage.getItem(LocalStorageKeys.SelectedUser, null);
		this.filterUser = userStorage.getItem(LocalStorageKeys.FilterUser, NavItemAuth.usersActive);
	}

	addDOM() {
		this.authModel = new auth.Model();
		this.authModel.build()
			.then(() => {
				this.setUsers();
				this.setGroups();
				this.setModules();
				this.createUserList();
			})
			.catch(err => {
				showNotification("Authentication service failure",
					tt("A error occurred while trying to connect to the authentication service. Please contact your System Administrator."));
			}); // just redraw once model is available
	}

	addEvents() { }
	destroy() { }
	resize() {
		if (!this.isUserLoaded) window.setTimeout(() => { this.createUserListWithAd(); }, 50);
		if (this.authUserList) this.authUserList.resize();
	}


	/** Set the user array */
	private setUsers() {
		this.users = this.authModel.users;
	}

	/** Set the group array */
	private setGroups() {
		this.groups = this.authModel.groups;
	}

	/**
	 * set array of modules active in the application
	 * we don't want unavailable modules to be shown  so the resultant array is a
	 * combination of enum items, available modules as set in conf and modules from associated roles/permissions.
	 */
	private setModules() {
		this.availableModules = [];

		// get a list of associated modules from the roles
		const roleModule: string[] = [];

		for (const i in auth.Permissions) {
			const authModule = auth.Permissions[i].module;
			const result = roleModule.filter(roleModule => roleModule === authModule);
			if (result.length === 0) roleModule.push(authModule);
		}

		for (const i in auth.AuthModule) {
			// use the name from the enum and see if it is available in the global modules
			const resultClientModule = Module.getPermissionedModules().filter(clientmodule => clientmodule.name?.toUpperCase() === auth.AuthModule[i].toUpperCase());
			// see if the enum is included in the list of modules from the roles/permissions
			const resultRoleModule = roleModule.filter(roleModule => roleModule.toString() === auth.AuthModule[i]);
			if (resultClientModule.length > 0 && resultRoleModule.length > 0) { // item found so add as available module
				this.availableModules.push({ id: i, value: auth.AuthModule[i] });
				continue;
			}

			// Check here if it was added dynamically and add it
			const isDynamicModule = auth.DynamicModules.filter(dynamicModule => dynamicModule === i);
			if (isDynamicModule.length > 0)
				this.availableModules.push({ id: i, value: auth.AuthModule[i] });

		}

		// sort
		this.availableModules = this.availableModules.sort((a, b) => {
			return a.value.localeCompare(b.value);
		});

		// add global module at top of array
		this.availableModules.unshift({ id: "MODULE_ACCESS", value: "Module Access" });
		this.availableModules.unshift({ id: "Global", value: "Global" });
	}

	/** Query the auth system to get the status of whether ad(ldap) is enabled */
	private createUserList() {
		const successAdStatus = (response) => {
			this.adStatus = response;
			this.createUserListWithAd();
		};

		const failureAdStatus = () => {
			this.adStatus = 0;
			this.createUserListWithAd();
		};

		ajaxJsonGET("auth2/hasactivedirectory", null, successAdStatus, failureAdStatus);
	}

	/** Instantiates class responsible for auth users */
	createUserListWithAd(): void {
		if (this.root.css("display") === "none") return;

		this.authUserList = new AuthUserList(this.rootID, this.users, this.groups, this.availableModules, this.adStatus, this.selectedUser, this.filterUser);
		this.authUserList.createUserList();

		this.authUserList.onSelectedUserChanged.subscribe((selectedUser: auth.User) => {
			this.selectedUser = selectedUser;
			userStorage.setItem(LocalStorageKeys.SelectedUser, selectedUser, false);
		});

		this.authUserList.onFilterChanged.subscribe((filterUser: number) => {
			this.filterUser = filterUser;
			userStorage.setItem(LocalStorageKeys.FilterUser, filterUser, false);
		});

		this.authUserList.onUserChanged.subscribe((selectedTabId: string) => {
			this.addDOM();
		});
		this.isUserLoaded = true;
	}
}

export class AuditTrailControl extends WidgetBase {
	private isAuditTrailLoaded: boolean;
	private containerID: string;
	private inputContainerID: string;

	constructor(rootID: string) {
		super(rootID);
		this.containerID = rootID + "container";
		this.inputContainerID = rootID + "-input-container";
	}

	addDOM() {
		this.root.empty();
		this.root.append(`<div id="${this.containerID}"></div>`);

		const vue = new Vue({
			template: `<auth-audit-trail />`,
			name: "auditTabWrapper",
			el: `#${this.containerID}`,
			components: {
				"auth-audit-trail": UserProfileAuditTrail
			},
			methods: {}
		});
	}

	addEvents() { }

	destroy() { }

	resize() { }
}

export class Groups extends WidgetBase {
	private isGroupLoaded: boolean;
	private groups: auth.Group[] = [];
	private availableModules: IModuleType[];
	private authModel?: auth.Model;
	private authGroupList?: AuthGroupList;

	addDOM() {
		this.destroy();

		this.authModel = new auth.Model();
		this.authModel.build()
			.then(() => {
				this.setGroups();
				this.setModules();
				this.createGroupList();
			})
			.catch(err => {
				showNotification("Authentication service failure",
					tt("A error occurred while trying to connect to the authentication service. Please contact your System Administrator."));
			}); // just redraw once model is available
	}

	addEvents() { }
	destroy() {
		this.authGroupList = undefined;
		this.authModel = undefined;
		this.isGroupLoaded = false;
	}

	resize() {
		if (!this.isGroupLoaded) window.setTimeout(() => { this.createGroupList(); }, 50);
		if (this.authGroupList) this.authGroupList.resize();
	}

	// Set the group array
	private setGroups() {
		if (this.authModel)
			this.groups = this.authModel.groups;
	}

	/*
	 * set array of modules active in the application
	 * we don't want unavailable modules to be shown  so the resultant array is a
	 * combination of enum items, available modules as set in conf and modules from associated roles/permissions.
	 */
	private setModules() {
		this.availableModules = [];

		// get a list of associated modules from the roles
		const roleModule: string[] = [];

		for (const i in auth.Permissions) {
			const authModule = auth.Permissions[i].module;
			const result = roleModule.filter(roleModule => roleModule === authModule);
			if (result.length === 0) roleModule.push(authModule);
		}

		for (const i in auth.AuthModule) {
			// use the name from the enum and see if it is available in the global modules
			const resultClientModule = Module.getPermissionedModules().filter(clientmodule => clientmodule.name?.toUpperCase() === auth.AuthModule[i].toUpperCase());
			// see if the enum is included in the list of modules from the roles/permissions
			const resultRoleModule = roleModule.filter(authModule => authModule.toString() === auth.AuthModule[i]);
			if (resultClientModule.length > 0 && resultRoleModule.length > 0) {// item found so add as available module
				this.availableModules.push({ id: i, value: auth.AuthModule[i] });
				continue;
			}

			// Check here if it was added dynamically and add it
			const isDynamicModule = auth.DynamicModules.filter(dynamicModule => dynamicModule === i);
			if (isDynamicModule.length > 0)
				this.availableModules.push({ id: i, value: auth.AuthModule[i] });
		}

		// sort
		this.availableModules = this.availableModules.sort((a, b) => {
			return a.value.localeCompare(b.value);
		});

		// add global module at top of array
		this.availableModules.unshift({ id: "MODULE_ACCESS", value: "Module Access" });
		this.availableModules.unshift({ id: "Global", value: "Global" });
	}

	// Instantiates class responsible for auth groups
	private createGroupList(): void {
		if (this.root.css("display") === "none") return;

		this.authGroupList = new AuthGroupList(this.rootID, this.groups, this.availableModules);
		this.authGroupList.createGroupList();

		this.authGroupList.onGroupChanged.subscribe((selectedTabId: string) => {
			this.addDOM();
		});
		this.isGroupLoaded = true;
	}
}

// Basically a copy of NavItemAuth ported to new tabbed navigation control
export class TabAuth extends WidgetBase {
	static usersActive = 0; // these could probably be moved to a ENUM but they work exactly the same like this and they are not used anywhere else
	static usersInActive = 1;
	static usersAll = 2;

	private contentDivID: string;
	private userControl: Users;
	private groupControl: Groups;

	constructor(rootID: string) {
		super(rootID);
		this.contentDivID = this.rootID + '-content';
		this.userControl = new Users(contentPaneID("energy-auth-tabs", "users"));
		this.groupControl = new Groups(contentPaneID("energy-auth-tabs", "groups"));
	}

	refresh() {
		this.addDOM();
		this.addEvents();
		this.userControl.refresh();
		this.groupControl.refresh();
	}

	addDOM() {
		// clear the content container
		const dims = windowDimensions();
		this.root.empty();
		this.root.append(
			`<div id='${this.contentDivID}' class='iq-energy-absolute-container' style='width: ${dims.height - GUI_NAV_HEIGHT - 1}px; height:${dims.width}px;'>
						<div id="energy-auth-tabs" style="width: 100%; height: 100%"></div>
					</div>`);
		setup("energy-auth-tabs", ["users", "groups"], [tt("Users"), tt("Groups")], true);

		setSelected("energy-auth-tabs", "users");
	}

	addEvents() {
		// slickgrid does not size correctly on a div that is not in the active viewport - so we render on first click
		$id(`energy-auth-tabs-btn-groups`).click(() => {
			this.groupControl.resize();
		});

		$id(`energy-auth-tabs-btn-users`).click(() => {
			this.userControl.resize();
		});
	}

	resize() {
		const dims = windowDimensions();
		$id(this.contentDivID).width(dims.width);
		$id(this.contentDivID).height(dims.height - GUI_NAV_HEIGHT - 1);
		resize("energy-auth-tabs");
		this.groupControl.resize();
		this.userControl.resize();
	}

	destroy() {
		if (this.userControl)
			this.userControl.destroyControl();
		if (this.groupControl)
			this.groupControl.destroyControl();
	}
}
