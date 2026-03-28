import Vue from 'vue';
import { parse, ParseResult } from 'papaparse';
import * as idata from '@imqs/idata';
import * as auth from '@imqs/auth';
import { isValidEmail } from '@imqs/root';
import { tt } from '@imqs/i18n';
import { Event } from '@imqs/event';
import { showDialog, showNotification } from "@imqs/components/Dialog";
import { FilterSearch } from '@imqs/components';
import { BrowserStore } from '../idata/transport_BrowserStore';
import { IHeaderMenuEventArgs } from '../third_party_extensions/slick.headermenu';
import { IModuleType, NavItemAuth } from '../nav/nav-source-auth';
import { $id } from '../js-base/utils';
import { FlatButtonControl, IFlatButtonOptions } from '../pcs/toolbar/flatbuttoncontrol';
import { FlatButtonState } from '../pcs/helperClasses/flatbutton';
import { FlatButtonAuthConst } from '../pcs/helperClasses/FlatButtonAuth';
import { IdataGrid, IdataGridHeaderCommandType } from '../grids/idata-grid';
import { IMaptoolContext } from '../maptools/maptool';
import { AuthUserPopup } from './authuserpopup';
import { startSpinner, stopSpinner } from '../widget/spinner';

const EXPECTED_USER_CSV_IMPORT_HEADER = ["name", "surname", "email", "mobile", "telephone", "remarks", "groups", "password"];

export interface IUserGroups {
	email: string;
	groups: string;
}

export class AuthUserList {
	onUserChanged: Event<string>;
	onSelectedUserChanged: Event<auth.User>;
	onFilterChanged: Event<number>;
	onSelectedRowChanged: Event<number>;
	private parentId: string;
	private csvFileImportId: string;
	private parentCtl: JQuery;
	private flatButtonControl: FlatButtonControl;
	private userGroups: auth.Group[];
	private userPermissions: auth.Permission[];
	private users: auth.User[];
	private allUsers: auth.User[];
	private groups: auth.Group[];
	private modules: IModuleType[];
	private selectedModule: string;
	private tableUser: idata.Table;
	private authUserCollection: idata.Collection;
	private filterUser: number;
	private gridUser: IdataGrid;
	private selectedUser?: auth.User;
	private adStatus: number;

	constructor(parentId: string, users: auth.User[], groups: auth.Group[], modules: IModuleType[], adStatus: number, selectedUser: auth.User, filterUser: number) {
		this.parentId = parentId;
		this.csvFileImportId = this.parentId + "-csv-file";
		this.parentCtl = $id(parentId);
		this.userGroups = [];
		this.users = users;
		this.allUsers = users;
		this.groups = groups;
		this.modules = modules;
		this.adStatus = adStatus;
		this.filterUser = filterUser;
		this.userPermissions = [];
		this.userGroups = [];
		this.selectedUser = selectedUser;
		this.onUserChanged = new Event();
		this.onSelectedUserChanged = new Event();
		this.onFilterChanged = new Event();
	}

	createUserList() {
		this.addDom();
		this.createToolbar();
		this.createUserGridFilters();
		this.createUserCollection();
		this.createUserTable();
		this.setUserGrid();
		this.attachUserEvents();

		if (this.selectedUser) {
			let id = this.tableUser.getByKey(this.selectedUser.userId);
			if (id)
				this.gridUser.onSelect.trigger([id]);
		}
		stopSpinner(this.parentId);
	}

	private addDom() {
		// reset
		this.parentCtl.empty();
		this.parentCtl.css("padding", "0");
		const html = `<div style="padding:0px 10px">
							<div id="${this.parentId}-user-top" class="auth-user-list-1">
								<div id="${this.parentId}-user-toolbar" class="auth-user-list-2"></div>
								<div id="${this.parentId}-user-filter" class="auth-user-list-3"></div>
								<div id="${this.parentId}-user-search" style="display: list-item;"></div>
							</div>
							<div id="${this.parentId}-user" class="auth-user-list-4"></div>
						</div>`;

		$id(this.parentId).append(html);

		const _self = this;

		const vue = new Vue({
			template: `<filter-search
							:data="allUsers"
							:fields="['email', 'username', 'name', 'surname']"
							placeholder="Search users"
							@visible="doFilterFields"
							@filterTextChanged="clearSelectedUser"
							:debounceTime=250
							style="width: 20%; float: right;"
						/>`,
			name: 'filterSearchWrapper',
			el: `#${this.parentId}-user-search`,
			components: {
				'filter-search': FilterSearch
			},
			data() {
				return {
					allUsers: _self.allUsers
				};
			},
			methods: {
				doFilterFields(visibleUsers) {
					_self.users = visibleUsers;
					_self.createUserTable();
					_self.setUserGrid();
					_self.setGridSelect();
				},
				clearSelectedUser() {
					_self.clearSelectedUser();
				}
			}
		});
	}

	// create the tool bar
	private createToolbar() {
		const toolButtons: IFlatButtonOptions[] = [];
		const addButtonState: FlatButtonState = auth.hasPermission(auth.Permissions.admin) ? FlatButtonState.ENABLED : FlatButtonState.DISABLED;
		const editButtonState: FlatButtonState = FlatButtonState.DISABLED;
		const currentUser = $.grep(this.users, function (user) { return user.userId == auth.getUserId(); })[0];

		if (currentUser && auth.isAdmin())
			toolButtons.push({ "state": addButtonState, "name": FlatButtonAuthConst.DocumentAdd, "method": this.uploadCSV.bind(this), "toolTip": tt("Add new users from CSV file") });
		toolButtons.push({ "state": addButtonState, "name": FlatButtonAuthConst.Add, "method": this.addEditUser(true), "toolTip": tt("Add new user") });
		toolButtons.push({ "state": editButtonState, "name": FlatButtonAuthConst.Edit, "method": this.addEditUser(false), "toolTip": tt("Edit selected user") });
		toolButtons.push({ "state": editButtonState, "name": FlatButtonAuthConst.Delete, "method": this.archiveUser.bind(this), "toolTip": tt("Delete selected user") });

		this.flatButtonControl = new FlatButtonControl(`${this.parentId}-user-toolbar`, toolButtons);
		this.flatButtonControl.createButtonObject();
		this.flatButtonControl.attachButtonEvents();
	}

	private uploadCSV(): void {
		$id(this.csvFileImportId).remove();
		$id(this.parentId).append(`<input type="file" id=${this.csvFileImportId} style="visibility:hidden">`);
		$id(this.csvFileImportId).change((event: any) => {
			const file = event.target.files[0];
			const reader = new FileReader();
			reader.onload = (event) => {
				const fileContent: string = <string>reader.result;
				if (!fileContent) {
					showNotification('Error', tt('Empty CSV file'));
					return;
				}
				this.parseCSV(fileContent);
			};
			reader.readAsText(file);
		});
		$id(this.csvFileImportId).click();
	}

	private parseCSV(fileContent: string) {
		const hasCsvErrors = (parseResult: ParseResult<string[]>): boolean => { // check CSV file: header, row lengths, emails, empty fields (password, mobile optional)
			if (parseResult.errors.length) {
				showNotification('Error', tt("CSV Parser error: ?1", parseResult.errors[0].message));
				return true;
			}
			if (parseResult.data.length < 2) {
				showNotification('Error', tt("Bad CSV: Missing header and/or data lines"));
				return true;
			}

			const compareStringArrays = (a: string[], b: string[]) => {
				if (a.length !== b.length) return false;
				for (let i = 0; i < a.length; i++)
					if (a[i] !== b[i]) return false;
				return true;
			};

			if (!compareStringArrays(parseResult.data[0], EXPECTED_USER_CSV_IMPORT_HEADER)) {
				showNotification('Error', tt("Bad CSV header. Expected: ?1", EXPECTED_USER_CSV_IMPORT_HEADER.toString()));
				return true;
			}

			let distinctEmails: string[] = [];
			for (let line = 1; line < parseResult.data.length; line++) { // iterate over csv lines (rows)
				if (parseResult.data[line].length !== EXPECTED_USER_CSV_IMPORT_HEADER.length) {
					showNotification('Error', tt("Bad CSV: Unexpected number of fields in line ?1", (line + 1).toString()));
					return true;
				}
				if (!isValidEmail(parseResult.data[line][EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("email")])) {
					showNotification('Error', tt("Bad CSV: Invalid email address in line ?1", (line + 1).toString()));
					return true;
				}
				if (distinctEmails.indexOf(parseResult.data[line][EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("email")]) === -1) {
					distinctEmails.push(parseResult.data[line][EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("email")]);
				} else {
					showNotification('Error', tt("Bad CSV: Duplicate email address in line ?1", (line + 1).toString()));
					return true;
				}

				for (let col = 0; col < parseResult.data[line].length; col++) {
					if ((parseResult.data[line][col] === "") && (col !== EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("password"))
						&& (col !== EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("mobile"))) {
						showNotification('Error',
							tt("Bad CSV: Empty field in line ?1 at field '?2'",
								(line + 1).toString(), EXPECTED_USER_CSV_IMPORT_HEADER[col]));
						return true;
					}
				}
			}
			return false;
		};

		const parseResult = parse<string[]>(fileContent, { delimiter: "," });
		if (hasCsvErrors(parseResult))
			return;
		this.checkGroupValidity(parseResult.data.splice(1)); // pass CSV data (excluding header) to next step
	}

	private checkGroupValidity(userData: string[][]) {
		let userModel = new auth.Model();
		userModel.build()
			.then(() => {
				for (let row = 0; row < userData.length; row++) {
					const groupData = parse<string[]>(userData[row][EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("groups")], { delimiter: " " }).data;
					for (let i = 0; i < groupData[0].length; i++) {
						if (!userModel.getGroupByName(groupData[0][i])) {
							showNotification('Error',
								tt("Invalid group name: ?1 in line ?2.  No users added",
									groupData[0][i].toString(), row + 1)
							);
							return;
						}
					}
				}
				this.addUsers(userData, userModel); // no group errors --> add users.
			});
	}

	private addUsers(userData: string[][], userModel: auth.Model) { // expects userdata [records][fields] parsed from csv.
		const failHandler = (message) => {
			showDialog(message, { header: tt('Error') });
			return;
		};

		let addedUsers: IUserGroups[] = []; // to be passed to setGroups
		let newUserCount = 0;
		for (let line = 0; line < userData.length; line++) {
			let user: auth.UserPostData = {
				firstname: userData[line][EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("name")],
				lastname: userData[line][EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("surname")],
				email: userData[line][EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("email")],
				mobilenumber: userData[line][EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("mobile")],
				telephonenumber: userData[line][EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("telephone")],
				remarks: userData[line][EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("remarks")],
			};

			if (userData[line].length === EXPECTED_USER_CSV_IMPORT_HEADER.length)
				user.password = userData[line][EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("password")];

			const successHandler = () => {
				let groups = userData[line][EXPECTED_USER_CSV_IMPORT_HEADER.indexOf("groups")];

				addedUsers.push({ email: user.email, groups: groups });
				if (line === userData.length - 1)
					this.setGroups(addedUsers, newUserCount);
			};

			if (userModel.getUserByName(user.email)) {	// existing user --> don't create new. Push, setGroups() if last user.
				successHandler();
			} else {									// new user --> create new, push, setGroups() if last user.
				newUserCount++;
				auth.createUser(user, () => successHandler(),
					(err: Error) => failHandler(tt("Adding users failed at line ?1 user ?2", (line + 1).toString(), user.email) + ".  " + tt("Error") + ": " + err));
			}
		}
	}

	private setGroups(addedUsers: IUserGroups[], newUserCount: number) {
		let userModel = new auth.Model();
		userModel.build()
			.then(() => {
				// for each addedUser, use its groups[] to add Group objects to existing userModel (newly added users don't yet have Groups). Then push to auth DB.
				for (let i = 0; i < addedUsers.length; i++) {	// outside loop: new users to be added
					for (const user of userModel.users) { // inside loop: userModel.users (contains new users with their userIds, but no groups yet)
						if (user.email !== addedUsers[i].email)
							continue;

						// matches new user (has group info which existing userModel lacks)

						const groupData = parse<string[]>(addedUsers[i].groups, { delimiter: " " }).data;
						for (const g of groupData[0]) {
							const group = userModel.getGroupByName(g);
							if (group && user.groups.indexOf(group) === -1) // user doesn't have group yet --> add to user in existing userModel
								user.groups.push(group);
						}

						auth.setUserGroups(user, // userModel User object (now containing new group info) is pushed to auth DB
							() => {
								if (i === addedUsers.length - 1) { // last user's groups set OK --> refresh user list
									this.onUserChanged.trigger("users");
									showNotification("Success",
										tt("Added ?1 new user(s) and set groups for ?2 user(s)",
											newUserCount, addedUsers.length.toString())
									);
								}
							},
							(err: Error) => {
								showNotification('Error',
									tt("Setting user groups failed. Error: " + err));
							}
						);
					}
				}
			})
			.catch((err: Error) => {
				showNotification('Error',
					tt("Setting user groups failed. Error: " + err));
			});
	}

	/**
	 * Archive the selected user
	 */
	private archiveUser(): void {
		if (!this.selectedUser) return;
		const theUser = this.selectedUser.username || this.selectedUser.email || "";

		const archive = () => {
			if (!this.selectedUser?.userId)
				return;

			auth.archiveUser(this.selectedUser.userId,
				() => {
					showNotification('Deleted',
						tt("User ?1 deleted", theUser));
					this.onUserChanged.trigger("users");
				},
				() => {
					showNotification('Error',
						tt("Deleting user ?1 failed", theUser));
					this.onUserChanged.trigger("users");
				}
			);
		};

		showDialog(tt("Delete user ?1?", theUser), {
			primaryButtonText: tt("Delete"),
			primaryButtonColour: "primary",
			primaryButtonAction: archive,
			secondaryButtonText: tt("Cancel")
		});
	}

	private createUserGridFilters() {
		const html = `<div>
					<div style="float:left;">
						<label style="font-size: 12px; margin-right: 5px;">User type </label>
						<select  style="font-size:11px;" id="${this.parentId}-filter-users">
							<option value="all" ${(this.filterUser === NavItemAuth.usersAll) ? "selected" : ""}>${tt("All Users")}</option>
							<option value="active" ${(this.filterUser === NavItemAuth.usersActive) ? "selected" : ""}>${tt("Active Users")}</option>
							<option value="inactive" ${(this.filterUser === NavItemAuth.usersInActive) ? "selected" : ""}>${tt("Inactive Users")}</option>
							<option value="deleted" ${(this.filterUser === NavItemAuth.usersDeleted) ? "selected" : ""}>${tt("Deleted Users")}</option>
						</select>
					</div>
					<div style="float:left;padding-left:10px">
						<label style="font-size: 12px; margin-right: 5px;">Module</label>
						<select style="font-size:11px;" id="${this.parentId}-filter-modules">
							<option selected value="None">${tt("All Modules")}</option>
						</select>
					</div>
				</div>`;

		$id(`${this.parentId}-user-filter`).append(html);

		// add the module option to the select
		if (this.modules) {
			this.modules.forEach((item) => {
				$id(`${this.parentId}-filter-modules`).append($("<option>", {
					value: item.value,
					text: tt(item.value)
				}));
			});
		}
	}

	/**
	 * create the browser store collection (this will contain the user table)
	 */
	private createUserCollection() {
		this.authUserCollection = new idata.Collection("AuthUser");
		this.authUserCollection.io.setTransport(BrowserStore.make(), 0);
	}

	/**
	 * create the BrowserStore table for users
	 */
	private createUserTable() {
		if (this.tableUser) {
			this.tableUser.clear();
		} else {
			this.setTableStructure();
		}

		// sort the users according to enabled and name
		this.users = this.users.sort((a: auth.User, b: auth.User) => {
			if (a.hasPermission(auth.Permissions.enabled) < b.hasPermission(auth.Permissions.enabled))
				return 1;
			if (a.hasPermission(auth.Permissions.enabled) > b.hasPermission(auth.Permissions.enabled))
				return -1;

			if (a.name && !b.name)
				return 1;
			if (!a.name && b.name)
				return -1;
			if (!a.name && !b.name)
				return 0;

			return a.name!.toLowerCase().localeCompare(b.name!.toLowerCase());
		});

		for (const user of this.users) {
			let enabled = "Inactive"; // default states
			let administrator = tt("No");
			let canAdd = false;
			let canAddModule = true;
			let hasRemarks = tt("No");

			if (this.selectedModule) canAddModule = this.selectedModule.toString() === "None" || this.selectedModule === auth.AuthModule.GLOBAL;

			for (const group of user.groups) {
				if (group.name === "enabled")
					enabled = "Active";
				if (group.name === "admin")
					administrator = tt("Yes");

				if (group.permissions.some(p => p.module === this.selectedModule))
					canAddModule = true;
			}

			if (user.remarks && user.remarks.length > 0)
				hasRemarks = tt("Yes");

			if (this.filterUser === NavItemAuth.usersActive && enabled === "Active" && !user.archived)
				canAdd = true;
			if (this.filterUser === NavItemAuth.usersInActive && enabled === "Inactive" && !user.archived)
				canAdd = true;
			if (this.filterUser === NavItemAuth.usersDeleted && user.archived)
				canAdd = true;
			if (this.filterUser === NavItemAuth.usersAll && !user.archived)
				canAdd = true;

			// create the record in the table
			if (canAdd && canAddModule && user.userId) {
				let userIdInt: number = +user.userId;
				const rec = this.tableUser.create({ id: userIdInt });
				rec.set("name", user.name);
				rec.set("surname", user.surname);
				// AuthUserType.IMQS's value is 0 therefore we cannot just check user.authUserType
				// since 'if (user.authUserType)' then evaluates to false.
				if (user.authUserType || user.authUserType === auth.AuthUserType.IMQS)
					rec.set("usertype", auth.authUserTypeToString(user.authUserType));
				rec.set("email", user.email);
				rec.set("username", user.username);
				rec.set("enabled", tt(enabled));
				rec.set("administrator", administrator);
				rec.set("archived", user.archived);
				rec.set("remarks", hasRemarks);
				rec.set("created", user.created);
				if (user.lastLoginDate === '0001-01-01T00:00:00Z') {
					rec.set("last_login_date", "");
				} else {
					rec.set("last_login_date", user.lastLoginDate);
				}
				if (user.enabledDate === '0001-01-01T00:00:00Z') {
					rec.set("enabled_date", "");
				} else {
					rec.set("enabled_date", user.enabledDate);
				}
				if (user.disabledDate === '0001-01-01T00:00:00Z') {
					rec.set("disabled_date", "");
				} else {
					rec.set("disabled_date", user.disabledDate);
				}
			}
		}
	}

	private setTableStructure(): void {
		// create the table in the collection
		this.tableUser = this.authUserCollection.tableByName("user", true)!;

		// set the fields on the table
		this.tableUser.type.setup("id", "name", "surname", "username", "email", "administrator", "usertype", "remarks");
		this.tableUser.type.keyIsUuid = false;

		// set the field types and aliases
		this.tableUser.type.fields[0].fieldType = "int64";
		this.tableUser.type.fields[1].alias = "Name";
		this.tableUser.type.fields[1].fieldType = "text";
		this.tableUser.type.fields[1].uiOrder = "1";
		this.tableUser.type.fields[1].group = "general";
		this.tableUser.type.fields[1].name = "name";
		this.tableUser.type.fields[1].fieldType = "text";
		this.tableUser.type.fields[2].alias = "Surname";
		this.tableUser.type.fields[2].fieldType = "text";
		this.tableUser.type.fields[3].alias = "Username";
		this.tableUser.type.fields[3].fieldType = "text";
		this.tableUser.type.fields[4].alias = "Email Address";
		this.tableUser.type.fields[4].fieldType = "text";
		this.tableUser.type.fields[5].alias = "Administrator";
		this.tableUser.type.fields[5].fieldType = "text";
		this.tableUser.type.fields[6].alias = "Account Type";
		this.tableUser.type.fields[6].fieldType = "text";
		this.tableUser.type.fields[7].alias = "Has Remarks";
		this.tableUser.type.fields[7].fieldType = "text";
	}

	/*
	 * set the grid using the browser store table
	 */
	private setUserGrid() {
		if (!this.tableUser)
			return;

		this.resize();
		const gridCols = ["name", "surname", "username", "email", "administrator", "usertype", "remarks"];

		this.gridUser = new IdataGrid(`${this.parentId}-user`, undefined, <IMaptoolContext>{},
			"", [this.tableUser], gridCols, undefined, 200, [], undefined,
			{ hideCloseButton: true }, { includeBelongsToTable: true, hideSort: false });

		this.gridUser.show();

		// Clear the selected user when the apply filter is clicked
		this.gridUser.headerPlugin?.onCommand.subscribe((e, args: IHeaderMenuEventArgs) => {
			if (args.command == IdataGridHeaderCommandType.Apply)
				this.clearSelectedUser();
		});
	}

	resize() {
		const width = $id(`${this.parentId}-user`).parent().parent().parent().width() || 0;
		const height = $id(`${this.parentId}-user`).parent().parent().parent().height() || 0;

		$id(`${this.parentId}-user`).width(width - 22);
		$id(`${this.parentId}-user`).height(height - 92);
	}

	private attachUserEvents() {
		$id(`${this.parentId}-filter-users`).change((eventData) => {
			switch ($(eventData.currentTarget).val()) {
				case "all":
					this.filterUser = NavItemAuth.usersAll;
					break;
				case "active":
					this.filterUser = NavItemAuth.usersActive;
					break;
				case "inactive":
					this.filterUser = NavItemAuth.usersInActive;
					break;
				case "deleted":
					this.filterUser = NavItemAuth.usersDeleted;
					break;
				default:
					this.filterUser = NavItemAuth.usersActive;
					break;
			}
			this.clearSelectedUser();

			this.onFilterChanged.trigger(this.filterUser);

			this.createUserTable();

			this.setUserGrid();

			this.setGridSelect();
		});

		$id(`${this.parentId}-filter-modules`).off("change").on("change", (eventData) => {
			this.selectedModule = <string>$(eventData.currentTarget).val();

			this.clearSelectedUser();

			this.createUserTable();

			this.setUserGrid();

			this.setGridSelect();
		});

		this.gridUser.selectRow.subscribe(() => {
			if (this.selectedUser) {
				let id = this.tableUser.getByKey(this.selectedUser.userId);
				if (id)
					this.gridUser.select([id]);
			}
		});

		this.setGridSelect();
	}

	clearSelectedUser() {
		this.flatButtonControl.changeButtonState(FlatButtonAuthConst.Delete, FlatButtonState.DISABLED);
		this.flatButtonControl.changeButtonState(FlatButtonAuthConst.Edit, FlatButtonState.DISABLED);
		this.selectedUser = undefined;
		this.onSelectedUserChanged.trigger();
	}

	private setGridSelect() {
		const f = (arg: idata.Record[]) => {
			// get the user id
			if (!arg[0])
				return;
			const userId = arg[0].get(0);

			// get the user from users list using id
			let user = this.users.find(u => u.userId === userId);
			if (!user)
				return;

			this.selectedUser = user;

			// set the toolbar
			this.flatButtonControl.changeButtonState(FlatButtonAuthConst.Delete, FlatButtonState.DISABLED); // default
			if (auth.hasPermission(auth.Permissions.admin)) {
				this.flatButtonControl.changeButtonState(FlatButtonAuthConst.Edit, FlatButtonState.ENABLED);
				// if the user is not the logged in user
				if (auth.getIdentity() !== this.selectedUser.email && this.selectedUser.isIMQSUser())
					this.flatButtonControl.changeButtonState(FlatButtonAuthConst.Delete, FlatButtonState.ENABLED);
			}
		};

		this.gridUser.onSelect.unsubscribe(f);
		this.gridUser.onSelect.subscribe(f);
	}

	private addEditUser(isAdd: boolean): () => void {
		return () => {
			if (isAdd) {
				this.selectedUser = undefined;
				this.gridUser.select([]);
				this.flatButtonControl.changeButtonState(FlatButtonAuthConst.Edit, FlatButtonState.DISABLED);
				this.flatButtonControl.changeButtonState(FlatButtonAuthConst.Delete, FlatButtonState.DISABLED);
			} else {
				this.onSelectedUserChanged.trigger(this.selectedUser);
			}

			const userPopup = new AuthUserPopup(`${this.parentId}-user`, this.selectedUser, this.groups, this.modules);
			const f = (isDirty: boolean) => {
				if (isDirty) {
					this.onUserChanged.trigger("users");

					// Reloading the user DOM takes time
					// During this regeneration process the user could still select
					// and view user records. This will clear the list and add a spinner.
					this.parentCtl.empty();

					startSpinner(this.parentId);
				}
			};
			userPopup.onUserDialogClosed.unsubscribe(f);
			userPopup.onUserDialogClosed.subscribe(f);
		};
	}
}
