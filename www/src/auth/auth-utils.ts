import { serverUrl } from 'lib/base/globals';
import { ajaxJsonGET, ajaxPOST, ajaxPUT, ajaxPOSTPromise } from 'lib/base/net';
import { tt } from 'lib/base/translate';
import { getUserId } from 'lib/auth/auth';
import { getPermissionByID, Permission, Permissions } from 'lib/auth/permissions';
import { logErr } from "lib/log/logger";
import { urlEncodeKVPairs } from "lib/base/uri";
import { Base64 } from "js-base64";
import { onreadystatechangeHandlerJson, onreadystatechangeHandlerString } from 'lib/auth';

/*
 NOTE: It might be a good idea to rename ts to auth-control.ts or something similar, indicating
 that this module is used to administer user permissions, as opposed to querying the permissions
 of the current session, which is performed inside imqs-ts
 */
export type AuthCallback = (request?: XMLHttpRequest) => void;

export const URL = "/auth2/";

export enum AuthUserType {
	IMQSUserType,
	LDAPUserType
}

export class AuthGroup {
	groupName: string;
	permissions: Permission[];

	constructor(groupName: string, permissions: Permission[]) {
		this.groupName = (groupName) ? groupName : "";
		this.permissions = (permissions) ? permissions : [];
	}
}

export function authUserTypeParse(t: number): AuthUserType {
	switch (t) {
		case 0:
			return AuthUserType.IMQSUserType;
		case 1:
			return AuthUserType.LDAPUserType;
		default:
			return AuthUserType.IMQSUserType;
	}
}

export function authUserTypeToString(authUserType: AuthUserType): string {
	switch (authUserType) {
		case AuthUserType.IMQSUserType:
			return "IMQS";
		case AuthUserType.LDAPUserType:
			return "LDAP";
		default:
			return "IMQS";
	}
}

export function serviceURL(call: string): string {
	return serverUrl(URL + call);
}

export class Model {
	users: User[];
	groups: Group[];

	constructor() {
		this.users = [];
		this.groups = [];
	}

	// queries auth service and builds up model of auth hierarchy to run UI from
	build(success, failure) {
		let gotUsers = (jsonResponse) => {
			this.users.length = 0;
			for (let jsonUser of jsonResponse) {
				const user = new User();
				user.parseFromGetUsers(this, jsonUser);
				this.users.push(user);
			}
			this.users.sort(this.sortCompareUsers);
			success(); // got everything we need
		};
		const gotGroups = (response) => {
			this.groups.length = 0;
			for (let i = 0; i < response.length; i++) {
				const group = new Group();
				group.parseFromGetGroups(this, response[i]);
				this.groups.push(group);
			}
			this.groups.sort(function compareGroups(a, b) {
				return a.name.toLowerCase().localeCompare(b.name.toLowerCase());
			});
			getUsers(gotUsers, failure, true);
		};
		getGroups(gotGroups, failure);
	}

	sortCompareUsers(user1: User, user2: User): number {
		if (user1.authUserType === AuthUserType.IMQSUserType && user2.authUserType === AuthUserType.IMQSUserType) {
			return user1.email.toLowerCase().localeCompare(user2.email.toLowerCase());
		} else if (user1.authUserType === AuthUserType.IMQSUserType && user2.authUserType === AuthUserType.LDAPUserType) {
			return user1.email.toLowerCase().localeCompare(user2.username.toLowerCase());
		} else if (user1.authUserType === AuthUserType.LDAPUserType && user2.authUserType === AuthUserType.IMQSUserType) {
			return user1.username.toLowerCase().localeCompare(user2.email.toLowerCase());
		} else {
			return user1.username.toLowerCase().localeCompare(user2.username.toLowerCase());
		}
	}

	getGroupByName(name: string): Group {
		for (let i = 0; i < this.groups.length; i++) {
			if (this.groups[i].name === name)
				return this.groups[i];
		}
		return null;
	}

	getUserByName(identity: string): User {
		for (let i = 0; i < this.users.length; i++) {
			const user = this.users[i];
			if (user.archived) continue;
			if (user.username === identity) {
				return user;
			} else if (user.email === identity) {
				return user;
			}
		}
		return null;
	}
}

export class User {

	userId: string;
	email: string;
	username: string;
	name: string;
	surname: string;
	mobileNumber: string;
	telephoneNumber: string;
	remarks: string;
	modified: string;
	modifiedBy: string;
	created: string;
	createdBy: string;
	archived: boolean;
	accountLocked: boolean;
	groups: Group[];
	authUserType: AuthUserType;

	constructor() {
		this.groups = [];
	}

	// parse response from getUsers
	parseFromGetUsers(authModel: Model, jUser: Object): void {
		this.email = jUser["Email"];
		this.userId = jUser["UserId"];
		this.username = jUser["Username"];
		this.name = jUser["Name"];
		this.surname = jUser["Surname"];
		this.mobileNumber = jUser["Mobile"];
		this.telephoneNumber = jUser["Telephone"];
		this.remarks = jUser["Remarks"];
		this.created = jUser["Created"];
		this.createdBy = jUser["CreatedBy"];
		this.modified = jUser["Modified"];
		this.modifiedBy = jUser["ModifiedBy"];
		this.archived = jUser["Archived"];
		this.accountLocked = jUser["AccountLocked"];
		this.authUserType = authUserTypeParse(jUser["AuthUserType"]);
		this.groups = [];

		const groupNames = jUser["Groups"];
		for (let i = 0; i < groupNames.length; i++) {
			const group = authModel.getGroupByName(groupNames[i]);
			if (group)
				this.groups.push(group);
			else
				logErr("Unrecognized auth group: " + groupNames[i]);
		}
	}

	// checks if user is a member of this group
	hasGroup(group: Group): boolean {
		for (let i = 0; i < this.groups.length; i++) {
			if (this.groups[i].name == group.name)
				return true;
		}
		return false;
	}

	hasPermission(role: Permission): boolean {
		for (let i = 0; i < this.groups.length; i++) {
			if (this.groups[i].hasPermission(role))
				return true;
		}
		return false;
	}

	isIMQSUser(): boolean {
		return this.authUserType == AuthUserType.IMQSUserType;
	}
}

export class Group {
	name: string;
	permissions: Permission[];
	moduleName?: string;

	constructor() {
		this.permissions = [];
	}

	// parse response from getGroups
	parseFromGetGroups(authModel: Model, jGroup: Object): void {
		this.name = jGroup["Name"];
		this.permissions = [];

		const permissionIds = jGroup["Roles"];
		for (let i = 0; i < permissionIds.length; i++) {
			const role = getPermissionByID(permissionIds[i]);
			if (role)
				this.permissions.push(role);
			else
				logErr("Unrecognized auth role: " + role);
		}
	}

	hasPermission(role: Permission): boolean {
		for (let i = 0; i < this.permissions.length; i++) {
			if (this.permissions[i].id == role.id)
				return true;
		}
		return false;
	}
}

// get latest roles for logged in user
export function check(success, failure) {
	ajaxJsonGET(serviceURL("check"), null, success, failure);
}

// Check if the username exists
export function checkEmailExists(email: string, password: string, success: (json: Object) => {}, fail: (reason: string) => {}) {
	const x = new XMLHttpRequest();
	x.open("GET", serverUrl('/auth2/check'), true);
	x.setRequestHeader("Authorization", "Basic " + Base64.encode(email + ":" + password));
	x.onreadystatechange = onreadystatechangeHandlerJson(x, success, fail);
	x.send();
}

// Send reset password start request
export function requestResetPassword(email: string, success: (res: any, stats: any) => void, failure: (req: XMLHttpRequest) => void) {
	const params = "?" + urlEncodeKVPairs({ "email": email });
	ajaxPOST(serverUrl('/auth2/reset_password_start' + params), null, success, failure);
}

// Send reset password finish request
export function setPassword(userid: string, password: string, token: string, success: (json: Object) => void, failure: (response: string) => void) {
	const x = new XMLHttpRequest();
	const params = "?" + urlEncodeKVPairs({ "userid": userid });
	x.open("POST", serverUrl('/auth2/reset_password_finish') + params, true);
	x.setRequestHeader("X-NewPassword", password);
	x.setRequestHeader("X-ResetToken", token);
	x.onreadystatechange = onreadystatechangeHandlerString(x, success, failure);
	x.send();
}

// Send set password request
export function updatePassword(identity: string, oldPassword: string, newPassword: string, success: (json: Object) => void, failure: (response: string) => void) {
	const x = new XMLHttpRequest();
	const params = "?" + urlEncodeKVPairs({ "email": identity });
	x.open("POST", serverUrl('/auth2/update_password') + params, true);
	x.setRequestHeader("X-OldPassword", oldPassword);
	x.setRequestHeader("X-NewPassword", newPassword);
	x.onreadystatechange = onreadystatechangeHandlerString(x, success, failure);
	x.send();
}

export function checkPassword(identity: string, password: string, success: (response: any) => void, fail: (response: string) => void) {
	const x = new XMLHttpRequest();
	x.open("POST", serverUrl('/auth2/check_password'), true);
	x.setRequestHeader("Authorization", "Basic " + Base64.encode(identity + ":" + password));
	x.onreadystatechange = onreadystatechangeHandlerString(x, success, fail);
	x.send();
}

// get list of users with their groups
export function getUsers(success, failure, includeDeleted = false) {
	const params = "?" + urlEncodeKVPairs({ "archived": includeDeleted });
	ajaxJsonGET(serviceURL("userobjects" + params), null, success, failure);
}

export function createUserWithPassword(email: string, username: string, password: string, name: string, surname: string, mobile: string, success, failure) {
	const params = "?" + urlEncodeKVPairs({
		"email": email,
		"username": username,
		"firstname": name,
		"lastname": surname,
		"mobilenumber": mobile,
		"password": password
	});
	ajaxPUT(serviceURL("create_user") + params, null, success, failure);
}

export function createUser(email: string, username: string, name: string, surname: string, mobile: string, telephone: string, remarks: string, success, failure) {
	const params = "?" + urlEncodeKVPairs({
		"email": email,
		"username": username,
		"firstname": name,
		"lastname": surname,
		"mobilenumber": mobile,
		"telephonenumber": telephone,
		"remarks": remarks
	});
	ajaxPUT(serviceURL("create_user") + params, null, success, failure);
}

export function updateUser(userid: string, email: string, username: string, firstname: string, lastname: string, mobile: string, telephone: string, remarks: string, authUserType: string, success, failure) {
	const params = "?" + urlEncodeKVPairs({
		"userid": userid,
		"email": email,
		"username": username,
		"firstname": firstname,
		"lastname": lastname,
		"mobilenumber": mobile,
		"telephonenumber": telephone,
		"remarks": remarks,
		"authusertype": authUserType
	});
	ajaxPOST(serviceURL("update_user") + params, null, success, failure);
}

export function unlockUser(userid: string, email: string, username: string, success: AuthCallback, failure: AuthCallback) {
	const params = "?" + urlEncodeKVPairs({
		"userid": userid,
		"username": username,
	});
	ajaxPOST(serviceURL("unlock_user") + params, null, success, failure);
}

export function archiveUser(userid: string, success, failure) {
	const params = "?" + urlEncodeKVPairs({ "userid": userid });
	ajaxPOST(serviceURL("archive_user") + params, null, success, failure);
}

export function createGroup(groupName: string, success, failure) {
	const params = "?" + urlEncodeKVPairs({ "groupname": groupName });
	ajaxPUT(serviceURL("create_group") + params, null, success, failure);
}

export function deleteGroup(groupName: string, success, failure) {
	const params = "?" + urlEncodeKVPairs({ "groupname": groupName });
	ajaxPUT(serviceURL("delete_group") + params, null, success, failure);
}

// get list of groups with their roles
export function getGroups(success, failure) {
	ajaxJsonGET(serviceURL("groups"), null, success, failure);
}

// set groups for user
export function setUserGroups(user: User, success, failure) {

	// some special rules so you don't lock yourself out of the application by accident
	if (getUserId() == user.userId) {
		if (!user.hasPermission(Permissions.admin)) {
			failure(tt("You cannot revoke your own administration rights"));
			return;
		}
		if (!user.hasPermission(Permissions.enabled)) {
			failure(tt("You cannot disable your own user"));
			return;
		}
	}

	const params = "?" + urlEncodeKVPairs({
		"userid": user.userId,
		"groups": user.groups.map(e => e.name).join()
	});

	ajaxPOST(serviceURL("set_user_groups") + params, null, success, failure);
}

// set permissions for group
export function setGroupPermissions(group: Group, success, failure) {
	const params = "?" + urlEncodeKVPairs({
		"groupname": group.name, "roles": group.permissions.map((e) => {
			return e.id;
		}).join()
	});
	ajaxPUT(serviceURL("set_group_roles") + params, null, success, failure);
}

export function updateGroup(groupName: string, newGroupName: string) {
	const params = "?" + urlEncodeKVPairs({
		'name': groupName,
		'newname': newGroupName
	});
	return ajaxPOSTPromise(serviceURL("update_group") + params, null);
}

// Rename username
export function renameUser(oldUser: string, newUser: string, password: string, success, failure) {
	const x = new XMLHttpRequest();
	const params = "?" + urlEncodeKVPairs({ "old": oldUser, "new": newUser });
	x.open("POST", serviceURL("rename_user") + params, true);
	x.setRequestHeader("Authorization", "Basic " + Base64.encode(oldUser + ":" + password));
	x.onreadystatechange = onreadystatechangeHandlerString(x, success, failure);
	x.send();
}

// Full email validation
export function isValidEmail(email: string): boolean {
	const re = /^([\w-]+(?:\.[\w-]+)*)@((?:[\w-]+\.)*\w[\w-]{0,66})\.([a-z]{2,6}(?:\.[a-z]{2})?)$/i;
	return re.test(email);
}
