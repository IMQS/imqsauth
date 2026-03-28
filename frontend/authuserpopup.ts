import * as auth from '@imqs/auth';
import { isValidEmail } from '@imqs/root';
import { showNotification, showDialog } from "@imqs/components/Dialog";
import { Event } from '@imqs/event';
import { tt } from '@imqs/i18n';
import { IModuleType } from '../nav/nav-source-auth';
import { $id } from '../js-base/utils';
import { PopUp } from '../pcs/popup';
import { IqDialogHorPos, IqDialogVerPos } from '../dialog/dialog';

export type AuthCallback = (request?: XMLHttpRequest) => void;

export class AuthUserPopup {
	onUserDialogClosed: Event<boolean>;
	private parentId: string;
	private parentCtl: JQuery;
	private popupId: string;
	private popup: PopUp;
	private selectedUser?: auth.User;
	private loggedInUser: auth.User;
	private isAdd: boolean;
	private dialogHeader: string;
	private isDirty: boolean;
	private groups: auth.Group[] = [];
	private modules: IModuleType[];
	private userGroups: auth.Group[];
	private userPermissions: auth.Permission[];
	private isImqsUser: boolean;
	private lockedUserDivID: string;

	constructor(parentId: string, selectedUser: auth.User | undefined, groups: auth.Group[], modules: IModuleType[]) {
		this.parentId = parentId;
		this.parentCtl = $id(parentId);
		this.popupId = `${parentId}-user-popup`;
		this.groups = groups;
		this.modules = modules;
		this.isAdd = selectedUser ? false : true;
		this.dialogHeader = selectedUser ? "Edit user" : "Add new user";
		this.isDirty = false;
		this.userGroups = [];
		this.userPermissions = [];
		this.lockedUserDivID = "auth-user-popup-account-locked";

		this.onUserDialogClosed = new Event();

		const authModel = new auth.Model();
		authModel.build()
			.then(() => {
				this.groups = authModel.groups;
			})
			.then(() => {
				this.getLoggedInUser().then(loggedInUser => {
					this.loggedInUser = loggedInUser;
					this.selectedUser = selectedUser
						? selectedUser
						: this.createNewUser();
					this.isImqsUser = this.selectedUser.isIMQSUser();
					this.showPopup();
				});
			});
	}

	showPopup() {
		this.popup = new PopUp(
			this.parentId,
			this.dialogHeader,
			this.popupId,
			this.addPopupUserContent(this.popupId),
			false,
			795,
			620,
			IqDialogVerPos.MIDDLE,
			IqDialogHorPos.CENTER
		);

		this.popup.createPopUp();
	}

	/**
	 * Create a new clean User
	 * Dont know why the original object was implemented in this way (not initialising members in constructor)
	 */
	private createNewUser(): auth.User {
		const user = new auth.User();

		const enabledGroup = this.getGroup("enabled");
		const date = new Date();

		user.authUserType = auth.AuthUserType.IMQS;
		user.email = "";
		user.groups = [];
		if (enabledGroup)
			user.groups.push(enabledGroup); // add enabled by default for new user
		user.mobileNumber = "";
		user.telephoneNumber = "";
		user.remarks = "";
		user.name = "";
		user.surname = "";
		user.userId = "";
		user.username = "";
		user.created = Date();
		user.createdBy = this.loggedInUser
			? `${this.loggedInUser.name} ${this.loggedInUser.surname}`
			: "";
		user.modified = Date();
		user.modifiedBy = this.loggedInUser
			? `${this.loggedInUser.name} ${this.loggedInUser.surname}`
			: "";
		user.lastLoginDate = Date();
		user.enabledDate = Date();
		user.disabledDate = Date();

		return user;
	}

	private getLoggedInUser(): Promise<auth.User> {
		const authModel = new auth.Model();
		let id = auth.getIdentity();
		if (!id)
			throw "Unable to get user id";
		return authModel.build().then(() => {
			let user = authModel.getUserByName(id!);
			if (!user)
				throw "Unable to get user";
			return user!;
		});
	}

	/**
	 * return the group containing the enabled permission
	 */
	private getGroup(groupName: string): auth.Group | undefined {
		return this.groups.find(g => g.name === groupName);
	}

	private addPopupUserContent(targetId: string) {
		return () => {
			this.createUserDom(targetId);
			this.createGroupsContainer(targetId);
			this.loadUser(targetId);
			this.addEvents(targetId);
		};
	}

	private createUserDom(targetId: string) {
		const disabledAdmin = this.isAdd ? "" : (auth.getIdentity() === this.selectedUser?.email || this.selectedUser?.archived) ? "disabled" : "";
		const disabled = this.isImqsUser && !this.selectedUser?.archived ? "" : "disabled";
		const required = this.isImqsUser ? "auth-label-required" : "";
		const accountlocked = this.selectedUser?.accountLocked
			? ""
			: "display: none;";

		const html = `
			<div class="auth-box">
				<div class="auth-section auth-section-locked"
					id="${this.lockedUserDivID}"
					style="${accountlocked}">
					<div class="auth-lock-text">
						${tt("This account is locked due to too many failed log in attempts.")}
					</div>
					<button id="${targetId}-accountLocked"
							class="g-button-primary auth-lock-button">Unlock</button>
				</div>
				<div id="${targetId}-information"
					class="auth-section auth-section-user">
					<label class="auth-section-label">${tt("Account Information")}</label>
					<div class="auth-column">
						<div class="auth-row">
							<div class="auth-input-label label-tall ${required}">${tt("Name")}</div>
							<div class="auth-input-cell">
								<input class="width-250" id="${targetId}-name" type="text" ${disabled}/>
							</div>
						</div>
						<div class="auth-row">
							<div class="auth-input-label label-tall ${required}">${tt("Surname")}</div>
							<div class="auth-input-cell">
								<input class="width-250" id="${targetId}-surname" type="text" ${disabled}/>
							</div>
						</div>
						<div class="auth-row">
							<div class="auth-input-label label-tall">${tt("Username")}</div>
							<div class="auth-input-cell">
								<input class="width-250" id="${targetId}-username" type="text" ${disabled}/>
							</div>
						</div>
						<div>
							<div class="auth-input-label label-tall">${tt("Remarks")}</div>
							<div class="auth-input-cell">
								<textarea class="auth-remarks-memo width-250" id="${targetId}-remarks" type="text" ${disabled}></textarea>
							</div>
						</div>
					</div>
					<div class="auth-column">
						<div class="auth-row">
							<div class="auth-input-label label-tall ${required}">${tt("Email")}</div>
							<div class="auth-input-cell">
								<input class="width-250" id="${targetId}-email" type="text" ${disabled}/>
							</div>
						</div>
						<div class="auth-row">
							<div class="auth-input-label label-tall">${tt("Mobile")}</div>
							<div class="auth-input-cell">
								<input class="width-250" id="${targetId}-mobile" type="text" ${disabled}/>
							</div>
						</div>
						<div class="auth-row">
							<div class="auth-input-label label-tall">${tt("Tel No")}</div>
							<div class="auth-input-cell">
								<input class="width-250" id="${targetId}-telephone" type="text" ${disabled}/>
							</div>
						</div>
						<div class="auth-row">
							<div class="auth-input-cell-div">
								<input class="auth-input" id="${targetId}-enabled" type="checkbox" ${disabledAdmin}/>
								<div class="auth-input-label label-short">${tt("Enabled User")}</div>
							</div>
						</div>
						<div class="auth-row">
							<div class="auth-input-cell-div">
								<input class="auth-input" id="${targetId}-administrator" type="checkbox" ${disabledAdmin}/>
								<div class="auth-input-label label-short">${tt("Administrator")}</div>
							</div>
						</div>
					</div>
				</div>

				<div class="auth-section auth-section-groups" id="${targetId}-groups">
					<label class="auth-section-label">${tt("Groups by Module")}</label>
					<label class="auth-section-label auth-section-label-permissions">
						${tt("Active Permissions")}
					</label>
					<div class="auth-list auth-list-groups" id="${targetId}-group-list"></div>
					<div class="auth-list auth-list-permissions" id="${targetId}-permissions-list" style="border-right: 0"></div>
				</div>

				<div class="auth-buttons-group">
					<div class="auth-updated">
						<div id="${targetId}-created"></div>
						<div id="${targetId}-modified"></div>
					</div>
					<div>
						<button id="${targetId}-cancel" class="g-button-neutral pcs_save_b">Cancel</button>
						<button id="${targetId}-save" class="g-button-primary pcs_save_b" disabled="disabled">Save</button>
					</div>
				</div>
			</div>`;

		$id(targetId + "popup-container").append(html);
	}

	/**
	 * This method seems unfinished. Im pretty sure the for-loop does nothing
	 * - Fritz
	 */
	private expandModuleLoad(targetId: string, group: auth.Group) {
		if (!group.name || group.name === "admin" || group.name === "enabled") return;

		let moduleName = "";
		for (const p of group.permissions) {
			if ($id(`${targetId}-${moduleName}-button`).text() === "+") {
				$id(`${targetId}-${moduleName}-button`).toggleClass(
					"iq-auth-button-minus"
				);
				$id(`${targetId}-${moduleName}-button`).text("-");
				$id(`${targetId}-${moduleName}-list`).show();
			}
		}

		this.changeGroups(targetId, true, group.name);
	}

	/**
	 * Populate the groups container with a list off all enabled modules/groups
	 */
	private createGroupsContainer(targetId: string) {
		const groupList = $id(`${targetId}-group-list`);
		const isModuleAccess = permissionName =>
			permissionName.indexOf("ModuleAccess") !== -1;
		const pushToGroup = (moduleGroup, group) => {
			if (
				moduleGroup.filter(modgroup => modgroup === group.name)
					.length === 0
			)
				moduleGroup.push(group.name);
		};

		//  add each of the available modules
		this.modules.forEach(availableModule => {
			const groupDiv = `
			<div class="auth-entity-div">
			<div>
			<div id="${targetId}-${availableModule.id}-button" class="iq-auth-button-plus">+</div>
			<div class="auth-entity">${availableModule.value}</div>
			</div>
			<div id="${targetId}-${availableModule.id}-list" class="auth-entity-list">
			</div>
			</div>`;

			groupList.append(groupDiv);

			// TODO move
			$id(`${targetId}-${availableModule.id}-list`).hide();

			$id(`${targetId}-${availableModule.id}-button`)
				.off("click")
				.on("click", event => {
					$(event.currentTarget).toggleClass("iq-auth-button-minus");

					if ($(event.currentTarget).text() === "+") {
						$(event.currentTarget).text("-");
						$id(`${targetId}-${availableModule.id}-list`).show();
					} else {
						$(event.currentTarget).text("+");
						$id(`${targetId}-${availableModule.id}-list`).hide();
					}
				});

			const moduleGroup: string[] = [];
			for (const group of this.groups) {
				for (const permission of group.permissions) {
					if (availableModule.value === permission.module.toString()) {
						if (permission.friendlyName !== "Administrator" &&
							permission.friendlyName !== "Enabled")
							pushToGroup(moduleGroup, group);
					}

					// Build Module Access category
					if (availableModule.value === auth.AuthModule.MODULE_ACCESS.toString() &&
						isModuleAccess(permission.name))
						pushToGroup(moduleGroup, group);
				}
			}

			// if we have no groups in the module then display a label
			if (moduleGroup.length === 0) {
				const noGroupHtml = `
							<div class="auth-module-group-div">
								<div class="auth-module-group-italic">${tt("No associated groups")}</div>
							</div>`;
				$id(`${targetId}-${availableModule.id}-list`).append(noGroupHtml);
			}

			const disabled = this.selectedUser?.archived ? "disabled" : "";

			for (let i = 0; i < moduleGroup.length; i++) {
				const groupHtml = `
					<div class="auth-module-group-div">
						<label>
						<input id="${availableModule.id}-${i}-check" class="auth-module-group-checkbox" type="checkbox" value="${moduleGroup[i]}" ${disabled}/>
						<div class="auth-module-group">${moduleGroup[i]}</div>
						</label>
					</div>`;

				$id(`${targetId}-${availableModule.id}-list`).append(groupHtml);

				$id(`${availableModule.id}-${i}-check`)
					.off("click")
					.on("click",
						(eventObject) => {
							this.changeGroups(targetId, $(eventObject.currentTarget).prop("checked"), <string>$(eventObject.currentTarget).val());
							this.setDirtyState(targetId);
						});
			}
		});
	}

	private loadUser(targetId: string) {
		if (!this.isAdd) {
			if (this.selectedUser) {
				// lock status
				if (this.selectedUser.accountLocked)
					$id(`${targetId}-accountLocked`).val("account locked");
				// text input
				if (this.selectedUser.name)
					$id(`${targetId}-name`).val(this.selectedUser.name);
				if (this.selectedUser.surname)
					$id(`${targetId}-surname`).val(this.selectedUser.surname);
				if (this.selectedUser.username)
					$id(`${targetId}-username`).val(this.selectedUser.username);
				if (this.selectedUser.email)
					$id(`${targetId}-email`).val(this.selectedUser.email);
				if (this.selectedUser.mobileNumber)
					$id(`${targetId}-mobile`).val(this.selectedUser.mobileNumber);
				if (this.selectedUser.telephoneNumber)
					$id(`${targetId}-telephone`).val(this.selectedUser.telephoneNumber);
				if (this.selectedUser.remarks)
					$id(`${targetId}-remarks`).val(this.selectedUser.remarks);
				// check boxes
				if (this.selectedUser.hasPermission(auth.Permissions.enabled))
					$id(`${targetId}-enabled`).attr("Checked", "true");
				if (this.selectedUser.hasPermission(auth.Permissions.admin))
					$id(`${targetId}-administrator`).attr("Checked", "true");
				// groups
				for (const group of this.groups) {
					if (this.selectedUser.hasGroup(group))
						this.expandModuleLoad(targetId, group);
				}
			}
		} else {
			$id(`${targetId}-enabled`).attr("Checked", "true");
			$id(`${targetId}-name`).focus();
		}

		if (!this.selectedUser)
			return;

		this.buildModifiedCreated(
			"Created by",
			this.selectedUser.created || "",
			this.selectedUser.createdBy || "",
			`${targetId}-created`
		);

		this.buildModifiedCreated(
			"Modified by",
			this.selectedUser.modified || "",
			this.selectedUser.modifiedBy || "",
			`${targetId}-modified`
		);
	}

	private buildModifiedCreated(
		type: string,
		date: string,
		person: string,
		id: string
	) {
		const d = new Date(date);
		const pad = s => (s < 10 ? "0" + s : s);
		let text: string = "";
		if (type)
			text = ` ${tt(type)}`;
		if (person)
			text += ` ${person}`;
		else
			text += ` unknown`;
		if (date && date != "0001-01-01T00:00:00Z")
			text += ` on ${pad(d.getDate())}/${pad(d.getMonth() + 1)}/${d.getFullYear()}`;
		else
			text += ` on unknown`;
		$id(`${id}`).text(text);
	}

	private addEvents(targetId: string) {
		// check dirty state on text input change
		$(
			`#${targetId}-name, #${targetId}-surname, #${targetId}-username, #${targetId}-email, #${targetId}-mobile, #${targetId}-telephone, #${targetId}-remarks`
		)
			.off("keyup")
			.on("keyup", () => {
				this.setDirtyState(targetId);
			});

		// check dirty state on checkbox click
		$(`#${targetId}-enabled, #${targetId}-administrator`)
			.off("click")
			.on("click", () => {
				this.setDirtyState(targetId);
			});

		$id(`${targetId}-cancel`)
			.off("click")
			.on("click", () => {
				if (this.isDirty) {
					showDialog(tt("Discard the changes you have made?"), {
						primaryButtonText: tt("Discard"),
						primaryButtonColour: "primary",
						primaryButtonAction: () => this.closeUserPopup(),
						secondaryButtonText: tt("Cancel"),
						safeHTMLonly: `<div style="font-size:11px;margin-top:5px;margin-bottom:5px;">${tt("Clicking on the discard button will cause you to")} <span style="font-weight:bold;"> ${tt("lose all your edits")}</span> ${tt("and take you back to the main screen.")}</div>
						<div style="font-size:11px;">${tt("Click on the cancel button if you want to continue editing this record.")}</div>`
					});
				} else {
					this.closeUserPopup();
				}
			});

		// save the user
		$id(`${targetId}-save`)
			.off("click")
			.on("click", () => {
				this.saveUser(targetId);
			});

		// unlock user
		$id(`${targetId}-accountLocked`)
			.off("click")
			.on("click", () => {
				this.unlockAccount(targetId);
			});
	}

	private setDirtyState(targetId: string) {
		if (!this.selectedUser)
			return;

		let checkDirty = false;

		// check text input dirty state
		if ($id(`${targetId}-name`).val() !== this.selectedUser.name)
			checkDirty = true;
		if ($id(`${targetId}-surname`).val() !== this.selectedUser.surname)
			checkDirty = true;
		if ($id(`${targetId}-username`).val() !== this.selectedUser.username)
			checkDirty = true;
		if ($id(`${targetId}-email`).val() !== this.selectedUser.email)
			checkDirty = true;
		if ($id(`${targetId}-mobile`).val() !== this.selectedUser.mobileNumber)
			checkDirty = true;
		if (
			$id(`${targetId}-telephone`).val() !==
			this.selectedUser.telephoneNumber
		)
			checkDirty = true;
		if ($id(`${targetId}-remarks`).val() !== this.selectedUser.remarks)
			checkDirty = true;
		// check checkbox input dirty state
		if (this.selectedUser.hasPermission(auth.Permissions.enabled) !== $id(`${targetId}-enabled`).prop("checked")) checkDirty = true;
		if (this.selectedUser.hasPermission(auth.Permissions.admin) !== $id(`${targetId}-administrator`).prop("checked")) checkDirty = true;
		// check the groups assigned

		let selectedUserGroupCount = 0;

		for (let i = 0; i < this.selectedUser.groups.length; i++) {
			if (
				this.selectedUser.groups[i].name !== "admin" &&
				this.selectedUser.groups[i].name !== "enabled"
			) {
				selectedUserGroupCount++;
			}
		}

		if (this.userGroups.length !== selectedUserGroupCount) {
			checkDirty = true;
		} else {
			// same length so check content
			for (const group of this.userGroups) {
				if (!this.selectedUser.hasGroup(group))
					checkDirty = true;
			}
		}

		this.isDirty = checkDirty;
		this.toggleSaveButton(targetId);
	}

	private saveUser(targetId: string) {
		const firstname = <string>$id(`${targetId}-name`).val();
		const lastname = <string>$id(`${targetId}-surname`).val();
		const username = <string>$id(`${targetId}-username`).val();
		const email = <string>$id(`${targetId}-email`).val();
		const mobilenumber = <string>$id(`${targetId}-mobile`).val();
		const telephonenumber = <string>$id(`${targetId}-telephone`).val();
		const remarks = <string>$id(`${targetId}-remarks`).val();
		const topGroups: auth.Group[] = [];

		if ($id(`${targetId}-enabled`).prop("checked")) {
			let enabled = this.getGroup("enabled");
			if (enabled)
				topGroups.push(enabled);
		}

		if ($id(`${targetId}-administrator`).prop("checked")) {
			let admin = this.getGroup("admin");
			if (admin)
				topGroups.push(admin);
		}

		const notifyUserCreateError = (err: Error) => {
			showDialog(
				tt(
					"An error occurred while trying to save the user information. Please contact your system administrator."
				),
				{
					header: tt("User create error"),
					longMessage: err.message
				}
			);
		};

		const notifyUserEditError = (err: Error) => {
			showDialog(
				tt(
					"An error occurred while trying to save the user information. Please contact your system administrator."
				),
				{
					header: tt("User edit error"),
					longMessage: err.message
				}
			);
		};

		const notifyUserCreated = email => {
			const body = tt(`User ${email} created`);
			showNotification("User Created", body);
		};

		if (!this.validateValues(targetId)) return;

		if (this.isAdd) {
			// create the User object
			auth.createUser({ email, username, firstname, lastname, mobilenumber, telephonenumber, remarks },
				() => {
					notifyUserCreated(email);
					this.updateGroups(email, username, topGroups);
				},
				request => {
					notifyUserCreateError(request);
				}
			);
		} else {
			if (this.isImqsUser) {
				auth.updateUser(
					{
						userid: this.selectedUser?.userId,
						email,
						username,
						firstname,
						lastname,
						mobilenumber,
						telephonenumber,
						remarks,
						authusertype: "DEFAULT"
					},
					() => { this.updateGroups(email, username, topGroups); },
					notifyUserEditError);
			} else {
				this.updateGroups(email, username, topGroups);
			}
		}
	}

	private unlockAccount(targetId: string) {
		if (!this.selectedUser?.userId || !this.selectedUser.username)
			return;

		const username = this.selectedUser.username;

		let notifyUserUnlockError = (err: Error) => {
			showDialog(tt("An error occurred while trying to unlock the user."), {
				header: tt("User edit error"),
				longMessage: err.message
			});
		};

		let userUnlockSuccess = () => {
			const body = `User ${username} unlocked`;
			if (this.selectedUser)
				this.selectedUser.accountLocked = false;
			$id(`${targetId}-accountLocked`).attr("disabled", "disabled");
			// Add a synthetic delay to give user a sense that the servive is doing something instead of a section just vanishing instantly
			setTimeout(() => {
				$id(this.lockedUserDivID).remove();
				showNotification("User unlocked", body);
			}, 500);
		};

		auth.unlockUser(this.selectedUser.userId, this.selectedUser.username, userUnlockSuccess, notifyUserUnlockError);
	}

	private updateGroups(email: string, username: string, topGroups: auth.Group[]): Promise<void> {
		const notifySetGroupError = () => {
			const body = tt(
				"An error occurred while trying to set the group. Please contact your system administrator."
			);
			showNotification("Set groups error", body);
		};

		const authModel = new auth.Model();

		return authModel.build()
			.then(() => {
				this.selectedUser = authModel.getUserByName(email); // get the created user
				if (this.selectedUser && this.selectedUser.username !== username) // Prevent incorrect matching on LDAP users with no email address
					this.selectedUser = authModel.getUserByName(username);
				if (!this.selectedUser)
					return;

				this.selectedUser.groups = this.userGroups;

				for (const topGroup of topGroups)
					this.selectedUser.groups.push(topGroup);

				auth.setUserGroups(this.selectedUser, () => { this.closeUserPopup(); }, notifySetGroupError); // update with user groups
			})
			.catch((err) => {
				const body = tt(
					"An error occurred while trying to connect to the authentication service. Please contact your System Administrator."
				);
				showNotification(tt("Authentication service failure"), body);
			});
	}

	/**
	 * Closes the popup
	 */
	private closeUserPopup() {
		this.onUserDialogClosed.trigger(this.isDirty);
		$(`#${this.popupId}`).dialog("destroy");
	}

	private validateValues(targetId: string): boolean {
		let isValid = true;

		if (this.isImqsUser) {
			// validate that all required fields are filled in
			if ($id(`${targetId}-name`).val() === "") isValid = false;
			if ($id(`${targetId}-surname`).val() === "") isValid = false;
			if ($id(`${targetId}-email`).val() === "") isValid = false;

			if (isValid) {
				// check the email value
				if (!isValidEmail(<string>$id(`${targetId}-email`).val())) {
					isValid = false;
					const body = tt("Please enter a valid email.");
					showNotification("Invalid Email", body);
				}
			} else {
				const body = tt(
					"Please fill in all required fields before saving"
				);
				showNotification("Missing required fields", body);
			}
		}

		return isValid;
	}

	/*
	 * set the save button dependant on the dirty state
	 */
	private toggleSaveButton(targetId: string) {
		// set to disabled
		const saveButton = $id(`${targetId}-save`);
		saveButton.attr("disabled", "disabled");

		if (this.isDirty) saveButton.removeAttr("disabled");
	}

	/*
	 * Manage the list of groups associated to the user
	 */
	private changeGroups(
		targetId: string,
		isChecked: boolean,
		groupName: string
	) {
		if (isChecked) {
			// add a group
			// find the target group
			const foundGroup = this.groups.filter(
				group => group.name === groupName
			);

			this.userGroups.push(foundGroup[0]);
		} else {
			// remove the group
			for (
				let iUserGroups = 0;
				iUserGroups <= this.userGroups.length - 1;
				iUserGroups++
			) {
				if (this.userGroups[iUserGroups].name === groupName) {
					this.userGroups.splice(iUserGroups, 1);
					break;
				}
			}
		}

		this.displayUserPermissions(targetId);

		this.setGroupCheck(isChecked, groupName);
	}

	/*
	 * A group can belong to one or more module so can appear in more than one
	 * location in group list, we need to make sure that all group checkboxes
	 * have the same display state
	 */
	private setGroupCheck(isChecked: boolean, groupName: string) {
		// get all the group checkboxes
		$(".auth-module-group-checkbox").each((i, elem) => {
			if ($(elem).val() === groupName) {
				if (isChecked) {
					$(elem).attr("Checked", "true");
				} else {
					$(elem).removeAttr("Checked");
				}
			}
		});
	}

	private displayUserPermissions(targetId: string) {
		// reset the permissions and clear DOM
		this.userPermissions = [];
		const permissionCtl = $id(`${targetId}-permissions-list`);
		permissionCtl.empty();

		for (const ug of this.userGroups) {
			for (const p of ug.permissions) {
				if (!this.userPermissions.some(userPermission => (userPermission.id === p.id))) {
					if (p.friendlyName !== "Administrator" && p.friendlyName !== "Enabled")
						this.userPermissions.push(p);
				}
			}
		}

		// sort according to module and name (with global always first)

		this.userPermissions = this.userPermissions.sort((a, b) => {
			if (a.module === auth.AuthModule.GLOBAL && b.module !== auth.AuthModule.GLOBAL)
				return -1;
			if (a.module !== auth.AuthModule.GLOBAL && b.module === auth.AuthModule.GLOBAL)
				return 1;

			if (a.module < b.module)
				return -1;
			if (a.module > b.module)
				return 1;
			if (a.friendlyName < b.friendlyName)
				return -1;
			if (a.friendlyName > b.friendlyName)
				return 1;
			return 0;
		});

		for (const p of this.userPermissions) {
			const permissionHtml =
				`<div class="auth-entity-div auth-permission">
					<div class="auth-entity auth-permission"> ${p.friendlyName} - </div>
					<div class="auth-entity-list auth-permission"> ${p.module} </div>
				</div>`;
			permissionCtl.append(permissionHtml);
		}
	}
}
