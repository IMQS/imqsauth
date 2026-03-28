// TODO: Fix stub of auth.getGroups module

describe('iq', () => {
	describe('auth', () => {
		test('authuserpopup', () => {

			// 			let setUserGroupsStub, getGroupsStub, getUsersStub, getUserbyNameStub;

			// 			before(() => {
			// 				getGroupsStub = sinon.stub(iq.auth, "getGroups").callsFake(() => {
			// 					return [
			// 						{
			// 							"Name": "admin",
			// 							"Roles": ["1"]
			// 						},
			// 						{
			// 							"Name": "enabled",
			// 							"Roles": ["2"]
			// 						}];
			// 				});

			// 				getUserbyNameStub = sinon.stub(iq.auth.Model.prototype, "getUserByName").callsFake(() => {
			// 					return {
			// 						"UserId": 1755,
			// 						"Email": "",
			// 						"Username": "SomeUser",
			// 						"Name": "Some",
			// 						"Surname": "User",
			// 						"Mobile": "",
			// 						"Groups": ["enabled", "admin"],
			// 						"AuthUserType": 1
			// 					};
			// 				});

			// 				getUsersStub = sinon.stub(iq.auth, "getUsers").callsFake(() => {
			// 					return [
			// 						{
			// 							"UserId": 1701,
			// 							"Email": "",
			// 							"Username": "OtherUser",
			// 							"Name": "Other",
			// 							"Surname": "User",
			// 							"Mobile": "",
			// 							"Groups": ["enabled", "admin"],
			// 							"AuthUserType": 1
			// 						},
			// 						{
			// 							"UserId": 1755,
			// 							"Email": "",
			// 							"Username": "SomeUser",
			// 							"Name": "Some",
			// 							"Surname": "User",
			// 							"Mobile": "",
			// 							"Groups": ["enabled", "admin"],
			// 							"AuthUserType": 1
			// 						},
			// 						{
			// 							"UserId": 1760,
			// 							"Email": "valid@email.com",
			// 							"Username": "ValidUser",
			// 							"Name": "Valid",
			// 							"Surname": "User",
			// 							"Mobile": "",
			// 							"Groups": ["enabled", "admin"],
			// 							"AuthUserType": 1
			// 						}];
			// 				});

			// 				setUserGroupsStub = sinon.stub(iq.auth, "setUserGroups");
			// 				setUserGroupsStub.returns(Promise.resolve(true));
			// 			});

			// 			after(() => {
			// 				getUsersStub.restore();
			// 				getGroupsStub.restore();
			// 				getUserbyNameStub.restore();
			// 				setUserGroupsStub.restore();
			// 			});

			// 			it('should enable the correct LDAP user with no email address (Bug: TI-1755)', () => {
			// 				$("body").append("<div id='test-parent-element'></div>"); // Define a parent element

			// 				const groups = [];
			// 				const modules = [];
			// 				const enabledGroup = new iq.auth.Group();
			// 				enabledGroup.name = "enabled";

			// 				const selectedUser = new iq.auth.User();
			// 				selectedUser.userId = "1755";
			// 				selectedUser.email = ""; // This caused the bug
			// 				selectedUser.username = "SomeUser";
			// 				selectedUser.name = "Some";
			// 				selectedUser.surname = "User";
			// 				selectedUser.groups = groups;
			// 				selectedUser.authUserType = iq.auth.AuthUserType.LDAPUserType;

			// 				const authUserPopup = new iq.auth.AuthUserPopup("test-parent-element", selectedUser, groups, modules);

			// 				// Wait for the popup to initiate
			// 				setTimeout(() => {
			// 					$id("test-parent-element-user-popup-enabled").click(); // Click the "Enabled user" checkbox
			// 					$id("test-parent-element-user-popup-save").click(); // Click on the save button
			// 					expect(setUserGroupsStub).to.have.been.calledWith(sinon.match.has('userId', 1755), sinon.match.any, sinon.match.any);
			// 				}, 10);
			// 			});
		});
	});
});
