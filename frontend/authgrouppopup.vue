<template>
	<div v-if="show"
		 class="auth-group-parent">
		<div class="auth-group-parent-overlay"></div>
		<div style="position: absolute; width: 100%; height: 100%;">
			<div class="dialog-mask">
				<div class="auth-group-popup-body">
					<div class="auth-group-popup-header">{{ dialogHeader }}
					</div>
					<div style="display: flex">
						<div class="auth-popup-main-group"
							 style="width: 55%">
							<div class="auth-group-div width-150">
								<div :class="groupNameClassStr"
									 :id="targetID+'-groupname-label'">{{ tt("Group Name") }}</div>
								<div class="auth-group-label">{{ tt("Module") }}</div>
								<div :class="permissionClassStr"
									 :id="targetID+'-permissions-label'">{{ tt("Permissions") }}</div>
							</div>
							<div class="auth-group-div width-250">
								<div class="auth-group-label">
									<input type="text"
										   v-model="groupName"
										   class="width-228" />
								</div>
								<div class="auth-group-label">
									<select data-placeholder="tt('Choose a Module')"
											:id="targetID+'-modules'"
											v-model="moduleName"
											@change="populateGroupPermissionsMap"
											style="width:402px;">
										<option v-for="module in modules"
												:key="module.id"
												:value="module.value">
											{{ tt(module.value) }}
										</option>
									</select>
								</div>
								<div class="auth-permission-checkboxes"
									 :id="targetID+'-permissions'">
									<div v-for="perm in groupPermissions"
										 :key="perm.id"
										 class="auth-permission-div">
										<label>
											<input :id="targetID+'-permissions-'+perm.id"
												   class="auth-permission-input"
												   :value="perm.id"
												   type="checkbox"
												   :checked="isPermissionChecked(perm)"
												   @change="togglePermissionChecked(perm)" />
											<div class="auth-permission">
												{{ perm.friendlyName }}
											</div>
										</label>
									</div>
								</div>
							</div>
						</div>
						<div class="auth-group-side-div">
							<div class="active-permissions-group">{{tt("Active Permissions")}}</div>
							<div class="permissions-group-content">
								<ul>
									<li v-for="perm in Array.from(mappedActivePermissions)"
										:key="perm[0]">
										<label class="permission-label">{{tt(perm[0])}}</label>
										<ul>
											<li v-for="p in perm[1]"
												:key="p.id"
												class="permission-li">
												{{p.friendlyName}}
											</li>
										</ul>
									</li>
								</ul>
							</div>
						</div>
					</div>
					<div class="auth-footer-buttons">
						<button :id="targetID+'-save'"
								class="g-button-primary pcs_save_b auth-group-button"
								@click="saveGroup"
								:disabled="!isDirty">Save</button>
						<button :id="targetID + '-cancel'"
								class="g-button-neutral pcs_save_b auth-group-button"
								@click="closeGroupPopup">Cancel</button>
					</div>
				</div>
			</div>
		</div>
	</div>
</template>

<script lang="ts">
import Vue from 'vue';
import { Component, Prop, Watch } from 'vue-property-decorator';
import * as auth from "@imqs/auth";
import { showDialog, showNotification } from '@imqs/components/Dialog';
import { tt } from '@imqs/i18n';
import { IModuleType } from 'js/nav/nav-source-auth';
import { isDefined } from '@imqs/root';

interface PermissionChecked {
	permission: auth.Permission;
	isChecked: boolean;
}

@Component({})
export default class AuthGroupPopup extends Vue {
	@Prop({
		type: String,
		default: () => {
			return "auth-user-popup";
		}
	}) targetID!: string;
	@Prop() selectedGroup?: auth.Group;
	@Prop({ type: Array, required: true }) groups!: auth.Group[];
	@Prop({ type: Boolean, required: true }) isAdd!: boolean;
	@Prop({ required: true }) timestamp!: Date;

	tt: (english: string, ...args: any[]) => string = tt;

	show: boolean = true;
	modulePermissions: auth.Permission[] = [];
	moduleNameInternal: string = "";
	moduleName: string = "";
	groupName: string = "";
	permissions: auth.Permission[] = [];

	isDirty: boolean = false;

	groupPermissionsMap: Map<string, PermissionChecked> = new Map<string, PermissionChecked>();
	// ensure that this is always sorted on update
	checkedPermissions: auth.Permission[] = [];

	groupNameClasses: string[] = [];
	permissionsClasses: string[] = [];
	defaultLabelClasses = Object.freeze(["auth-group-label"]);

	created() {
		this.permissions = this.selectedGroup?.permissions.slice() || [];
		this.onSelectedGroupChange();
	}

	private get groupNameClassStr(): string {
		this.defaultLabelClasses.forEach(dc => {
			if (!isDefined(this.groupNameClasses.find(s => s === dc)))
				this.groupNameClasses.push(dc);
		});

		return this.groupNameClasses.join(" ");
	}

	private get checkedPermissionsLength(): number {
		return this.checkedPermissions?.length || 0;
	}

	private get permissionClassStr(): string {
		this.defaultLabelClasses.forEach(dc => {
			if (!isDefined(this.permissionsClasses.find(s => s === dc)))
				this.permissionsClasses.push(dc);
		});

		return this.permissionsClasses.join(" ");
	}

	get changeTracker() {
		return { checkPermissionsLength: this.checkedPermissionsLength, groupName: this.groupName };
	}

	@Watch("changeTracker")
	computeIsDirty() {
		// [JKG 2021-05-20]
		// This should be made a computed property - I just had too little time
		// to do it on this day
		if ((this.checkedPermissions?.length || 0) !== (this.selectedGroup?.permissions?.length || 0)) {
			this.isDirty = true;
			return;
		}

		const perms = this.selectedGroup?.permissions || [];
		for (let i = 0; i < perms.length; i++) {
			if (perms[i].friendlyName !== this.checkedPermissions[i].friendlyName) {
				this.isDirty = true;
				return;
			}
		}

		if (this.originalName !== this.groupName) {
			this.isDirty = true;
			return;
		}

		this.isDirty = false;
	}

	@Watch("timestamp")
	onSelectedGroupChange(): void {
		this.groupName = this.selectedGroup?.name || "";
		// [JKG 2021-05-11]
		// Figuring out the moduleName at the moment is hacky as hell.
		// The selectedGroup does not have a module associated with it.
		// We are making the educated guess here, based on prior business
		// decisions, that every group is associated with only one module.
		// This means that we ought to be able to pick ANY random permission
		// (which does have the module information) and we should be able to see
		// what the module associated with the permissions are.
		// If this business requirement changes, this is likely the place that
		// one fixes this logic.
		// the computed property will handle the reading of the checked
		// permissions, so there ought to be no need to try and figure it out
		// in this watcher
		this.moduleName = this.selectedGroup?.moduleName || this.selectedGroup?.permissions?.find(() => true)?.module || "";
		this.show = true;
		this.groupNameClasses = [];
		this.permissionsClasses = [];
		this.isDirty = false;
		this.populateGroupPermissionsMap();
	}

	// used in component
	private get modules(): IModuleType[] {
		return Object.entries(auth.AuthModule).map(([key, value]) => {
			return { id: key, value: value };
		});
	}

	private get allPermissions(): auth.Permission[] {
		let perms: auth.Permission[] = [];

		// get permissions that match the module that was passed
		for (const [key, permission] of Object.entries(auth.Permissions)) {
			if (this.shouldDisplay(permission)) {
				if (perms.indexOf(permission) === -1)
					perms.push(permission);
			}

			// Build up the module access permission list
			if (this.moduleName === auth.AuthModule.MODULE_ACCESS.toString() && this.isModuleAccessPermission(key)) {
				if (perms.indexOf(permission) === -1)
					perms.push(permission);
			}
		}
		return perms.sort((a, b) => a.friendlyName.localeCompare(b.friendlyName));
	}

	get modules2Permissions(): Readonly<Map<string, auth.Permission[]>> {
		let m = new Map<string, auth.Permission[]>();
		for (const value of this.allPermissions) {
			if (m.has(value.module)) {
				m.set(value.module, [...(m.get(value.module)!), value]);
			} else {
				m.set(value.module, [value]);
			}
		}
		return Object.freeze(m);
	}

	get dialogHeader(): string {
		let t = "Edit group";
		if (this.isAdd) t = "Add new group";
		return tt(t);
	}

	private isModuleAccessPermission(permissionName: string): boolean {
		return permissionName.indexOf('ModuleAccess') !== -1;
	}

	private shouldDisplay(permission: auth.Permission): boolean {
		// [JKG 2021-05-10]
		// Relic of some logic that I found when porting this to Vue
		// we don't allow Administrator and Enabled to be assigned to a group
		// (they should be in their own group already) - this is extremely hacky
		return !["Administrator", "Enabled"].includes(permission.friendlyName.toString());
	}

	private get originalName(): string {
		if (this.isAdd)
			return "";
		return this.selectedGroup?.name || "";
	}

	populateGroupPermissionsMap(): void {
		// computations on every re-compute
		this.groupPermissionsMap.clear();
		this.checkedPermissions = [];
		const selectedPermissions = this.permissions || [];

		// Determines whether or not the permission belongs to the selected group
		for (const groupPermission of this.groupPermissions) {

			let permissionChecked: PermissionChecked = <PermissionChecked>{ permission: groupPermission };
			const idx = selectedPermissions.indexOf(groupPermission);
			if (idx !== -1) {
				permissionChecked.isChecked = true;
				this.checkedPermissions.push(groupPermission);
			} else {
				permissionChecked.isChecked = false;
			}
			this.groupPermissionsMap.set(groupPermission.friendlyName, permissionChecked);
		}
		for (const selectedPermission of selectedPermissions) {
			if (this.checkedPermissions.indexOf(selectedPermission) == -1)
				this.checkedPermissions.push(selectedPermission);
		}
		this.checkedPermissions.sort((a, b) => a.friendlyName.localeCompare(b.friendlyName));
	}

	get groupPermissions(): auth.Permission[] {
		return this.modules2Permissions?.get(this.moduleName) || [];
	}

	get mappedActivePermissions(): Map<string, auth.Permission[]> {
		let activePermissions: Map<string, auth.Permission[]> = new Map<string, auth.Permission[]>();
		for (let checked of this.checkedPermissions) {
			if (!activePermissions.has(checked.module)) {
				let perms: auth.Permission[] = [];
				// add permission
				perms.push(checked);
				activePermissions.set(checked.module, perms);

			} else if (activePermissions.has(checked.module)) {
				// update permissions
				let perms = activePermissions.get(checked.module)!;
				perms.push(checked);
				activePermissions.set(checked.module, perms);
			}
		}
		return activePermissions;
	}

	private async updateGroupName(): Promise<void> {
		// Only update if the name has changed
		if (this.groupName === this.originalName || !this.selectedGroup?.name)
			return;

		return auth.updateGroup(this.selectedGroup.name, this.groupName)
			.then(() => {
				this.closeGroupPopup();
			})
			.catch(error => {
				const body = tt(
					"An error occurred while trying to update the group. Please contact your system administrator."
				);
				showNotification(tt("Update groups error"), body);
				throw error;
			});
	}

	private async saveGroup() {
		const onGroupNameSaveFinish = () => {
			this.setSelectedGroupPermissions();
			// at this point the group has been created
			// refresh the groups
			const authModel = new auth.Model();
			authModel.build()
				.then(() => {
					this.$emit("newGroups", authModel.groups);
					showNotification("Success", `Group ${this.groupName} ${this.isAdd ? "created" : "updated"}`);
				})
				.catch(err => {
					const body = tt(
						"A error occurred while trying to connect to the authentication service. Please contact your System Administrator."
					);
					showNotification("Authentication service failure", body);
				});
		};

		const notifyGroupCreateError = () => {
			const body = tt(
				"An error occurred while trying to save the group information. Please contact your system administrator."
			);
			showNotification("Group create error", body);
		};

		// validate values
		if (!this.validateGroup()) {
			const body = tt("Please fill in all required fields before saving");
			showNotification("Missing required fields", body);
			return;
		}
		// check that group name does not already exist
		if (this.groupExists()) {
			const body = tt("A group with the same name already exists.");
			showNotification("Group exists", body);
			return;
		}

		if (this.isAdd) {
			auth.createGroup(
				this.groupName,
				onGroupNameSaveFinish,
				notifyGroupCreateError
			);
		} else {
			await this.updateGroupName();
			onGroupNameSaveFinish();
		}
	}

	private setSelectedGroupPermissions() {
		const notifySetPermissionError = () => {
			const body = tt("An error occurred while trying to set the group permissions. Please contact your system administrator.");
			showNotification("Set permissions error", body);
		};
		const group = new auth.Group(this.groupName, this.checkedPermissions);
		auth.setGroupPermissions(group, () => { this.forceClose(); }, notifySetPermissionError);
	}

	/**
	 * check if the group name already exists, uses the originalname for edits
	 * (else a edit will return a true)
	 */
	private groupExists(): boolean {
		if (!this.groupName || this.groupName == "" || this.originalName === this.groupName)
			return false;

		return this.groups?.some(g => this.groupName === g.name) || false;
	}

	// Component handler which very simply checks if the permission has been checked, adds it to an array
	private togglePermissionChecked(perm: auth.Permission): void {
		if (!this.groupPermissionsMap.has(perm?.friendlyName || ""))
			this.groupPermissionsMap.set(perm.friendlyName, <PermissionChecked>{
				permission: perm,
				isChecked: false // init with false so that it flips correctly
			});

		let p = this.groupPermissionsMap.get(perm.friendlyName)!;
		p.isChecked = !p.isChecked;
		if (p.isChecked) {
			this.checkedPermissions.push(p.permission);
		} else {
			this.checkedPermissions = this.checkedPermissions.filter((cp) => cp.id !== p.permission.id);
		}
		this.checkedPermissions.sort((a, b) => a.friendlyName.toLowerCase().localeCompare(b.friendlyName.toLowerCase()));
		this.permissions = this.checkedPermissions;
		this.groupPermissionsMap.set(perm.friendlyName, p);
	}

	private isPermissionChecked(perm: auth.Permission): boolean {
		const p = this.groupPermissionsMap?.get(perm.friendlyName);
		return p?.isChecked || false;
	}

	private forceClose() {
		this.show = false;
		this.permissions = this.selectedGroup?.permissions || [];
		this.populateGroupPermissionsMap();
		this.$emit("close");
	}

	/**
	 * Closes the popup
	 */
	private closeGroupPopup() {
		if (this.isDirty) {
			showDialog(tt("Discard the changes you have made?"), {
				primaryButtonText: tt("Discard"),
				primaryButtonColour: "primary",
				primaryButtonAction: () => {
					this.forceClose();
				},
				secondaryButtonText: tt("Cancel"),
				safeHTMLonly: `<div style="font-size:11px;margin-top:5px;margin-bottom:5px;">${tt("Clicking on the discard button will cause you to")} <span style="font-weight:bold;"> ${tt("lose all your edits")}</span> ${tt("and take you back to the main screen.")}</div>
							<div style="font-size:11px;">${tt("Click on the cancel button if you want to continue editing this record.")}</div>`
			});
			return;
		}
		this.forceClose();
	}

	/**
	 * Validate the input of the group dialog, returns false if all required not filled
	 */
	private validateGroup(): boolean {
		// reset classes to default
		this.groupNameClasses = [];
		this.permissionsClasses = [];

		let isValid = (this.checkedPermissions?.length || 0) > 0;

		if (!isValid) {
			this.permissionsClasses = ["auth-group-label-red"];
		}

		if (this.groupName === "") {
			isValid = false;
			this.groupNameClasses = ["auth-group-label-red"];
		}

		return isValid;
	}
}
</script>

<style lang="less">
.auth-group-parent {
	position: fixed;
	left: 0;
	top: 0;
	width: 100%;
	height: 100%;
}

.auth-group-parent-overlay {
	position: absolute;
	width: 100%;
	height: 100%;
	background: rgba(0, 0, 0, 0.3);
}
.auth-group-popup-body {
	width: 1000px;
	height: auto;
	background-color: white;
	display: flex;
	flex-direction: column;
	.auth-group-popup-header {
		background-color: rgb(239, 239, 239);
		font-weight: 600;
		padding: 9px;
	}
	.auth-footer-buttons {
		display: flex;
		flex: 0 0 22px;
		justify-content: flex-end;
		z-index: 2000;
		right: 0px;
		padding: 10px;
		.auth-group-button {
			flex: 0 0 auto;
			height: 15px;
		}
	}
}
</style>
