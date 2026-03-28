import Vue from 'vue';
import * as idata from '@imqs/idata';
import * as auth from '@imqs/auth';
import { tt } from '@imqs/i18n';
import { showDialog, showNotification } from "@imqs/components/Dialog";
import { Event } from '@imqs/event';
import FilterSearch from '@imqs/components/FilterSearch/FilterSearch.vue';
import { BrowserStore } from '../idata/transport_BrowserStore';
import { FlatButtonAuthConst } from '../pcs/helperClasses/FlatButtonAuth';
import { IModuleType } from '../nav/nav-source-auth';
import { $id } from '../js-base/utils';
import { FlatButtonControl, IFlatButtonOptions } from '../pcs/toolbar/flatbuttoncontrol';
import { FlatButtonState } from '../pcs/helperClasses/flatbutton';
import { IdataGrid } from '../grids/idata-grid';
import { IMaptoolContext } from '../maptools/maptool';
import AuthGroupPopup from './authgrouppopup.vue';
import { elrem } from '@imqs/root';
import { tickStep } from 'd3-array';

export class AuthGroupList {
	onGroupChanged: Event<string>;
	private parentId: string;
	private parentCtl: JQuery;
	private flatButtonControl: FlatButtonControl;
	private authGroupCollection: idata.Collection;
	private tableGroup: idata.Table;
	private groups: auth.Group[];
	private allGroups: auth.Group[] = [];
	private modules: IModuleType[];
	private gridGroup: IdataGrid;
	private selectedGroup: auth.Group | null;
	private control: Vue | null;
	private timestampPopupOpened: Date;

	constructor(parentId: string, groups: auth.Group[], modules: IModuleType[]) {
		this.parentId = parentId;
		this.parentCtl = $id(parentId);
		this.groups = groups;
		this.modules = modules;
		this.selectedGroup = null;
		this.onGroupChanged = new Event();
		this.control = null;
	}

	createGroupList() {
		this.addDom();
		this.createToolbar();
		this.createGroupCollection();
		this.createGroupTable();
		this.setGroupGrid();
		this.attachGroupEvents();
	}

	private addDom() {

		// reset
		this.parentCtl.empty();
		this.parentCtl.css("display", "flex");
		this.parentCtl.css("padding", "0");
		const html = `<div style="height:auto;width:100%;padding:0px 10px;box-sizing:border-box">
								<div id="${this.parentId}-group-top" class="auth-group-list-1">
									<div id="${this.parentId}-group-toolbar" class="auth-group-list-2"></div>
									<div id="${this.parentId}-group-search" style="display: list-item;"></div>
								</div>
								<div id="${this.parentId}-group" class="auth-group-list-3"></div>
							</div>`;

		$id(this.parentId).append(html);

	}

	private createToolbar() {
		const toolButtons: IFlatButtonOptions[] = [];
		const addButtonState: FlatButtonState = auth.hasPermission(auth.Permissions.admin)
			? FlatButtonState.ENABLED
			: FlatButtonState.DISABLED;
		const editButtonState: FlatButtonState = FlatButtonState.DISABLED;

		toolButtons.push({
			"state": addButtonState,
			"name": FlatButtonAuthConst.Add,
			"method": this.addEditGroup(true),
			"toolTip": tt("Add new group")
		});
		toolButtons.push({
			"state": editButtonState,
			"name": FlatButtonAuthConst.Edit,
			"method": this.addEditGroup(false),
			"toolTip": tt("Edit selected group")
		});
		toolButtons.push({
			"state": editButtonState,
			"name": FlatButtonAuthConst.Delete,
			"method": this.deleteGroup.bind(this),
			"toolTip": tt("Delete selected group")
		});

		this.flatButtonControl = new FlatButtonControl(`${this.parentId}-group-toolbar`, toolButtons);
		this.flatButtonControl.createButtonObject();
		this.flatButtonControl.attachButtonEvents();
	}

	private setupVueComponent(isAdd: boolean): void {
		this.timestampPopupOpened = new Date();
		let self = this;

		const divID = `${this.parentId}-group-popup-vue`;
		if (!document.getElementById(divID)) {
			let div = document.createElement("div");
			div.id = divID;
			document.body.appendChild(div);
		}

		if (isAdd) {
			this.selectedGroup = null;
			this.gridGroup.select([]);
			this.flatButtonControl.changeButtonState(FlatButtonAuthConst.Edit, FlatButtonState.DISABLED);
			this.flatButtonControl.changeButtonState(FlatButtonAuthConst.Delete, FlatButtonState.DISABLED);
		}

		if (!this.control) {
			this.control = new Vue({
				el: `#${divID}`,
				data: () => {
					return {
						selectedGroup: this.selectedGroup,
						groups: this.groups,
						modules: this.modules,
						isAdd: isAdd,
						timestamp: this.timestampPopupOpened
					};
				},
				components: {
					"app-auth-user-popup": AuthGroupPopup
				},
				template: `
				<app-auth-user-popup :selectedGroup="selectedGroup"
									 :groups="groups"
									 :modules="modules"
									 :isAdd="isAdd"
									 :timestamp="timestamp"
									 @newGroups="save"
									 @close="close" />
				`,
				methods: {
					close: () => {
						destroy();
					},
					save: (groups: auth.Group[]) => {
						self.groups = groups;
						self.onGroupChanged.trigger("groups");
						destroy();
					}
				}
			});

			let destroy = () => {
				elrem(divID);
				this.control = null;
			};
		} else {
			console.log("THIS CODE SHOULD NOT HIT");

			this.control.$data["isAdd"] = isAdd;
			this.control.$data["groups"] = this.groups;
			this.control.$data["selectedGroup"] = this.selectedGroup;
			this.control.$data["timestamp"] = new Date();
			this.control.$forceUpdate();
		}
	}

	private addEditGroup(isAdd: boolean): () => void {
		const groupPopup = () => {
			this.setupVueComponent(isAdd);
		};
		return groupPopup;
	}

	/**
	 * Delete the selected group
	 */
	private deleteGroup() {
		if (!this.selectedGroup?.name)
			return;
		const groupName = this.selectedGroup.name;
		const deleteSuccess = () => {
			showNotification('Deleted',
				tt("Group ?1 deleted", groupName));
			this.onGroupChanged.trigger("groups");
		};
		const deleteFailed = () => {
			showNotification('Error',
				tt("Deleting group ?1 failed", groupName));
			this.onGroupChanged.trigger("groups");
		};
		showDialog(tt("Delete group ?1?", groupName), {
			primaryButtonText: tt("Delete"),
			primaryButtonColour: "primary",
			primaryButtonAction: () => auth.deleteGroup(groupName, deleteSuccess, deleteFailed),
			secondaryButtonText: tt("Cancel")
		});
	}

	/**
	 * create the browser store collection (this will contain the group table)
	 */
	private createGroupCollection() {
		this.authGroupCollection = new idata.Collection("AuthGroup");
		this.authGroupCollection.io.setTransport(BrowserStore.make(), 0);
	}

	/**
	 * create the BrowserStore table for groups
	 */
	private createGroupTable() {
		if (this.tableGroup) {
			this.tableGroup.clear();
		} else {
			this.setTableStructure();
		}

		this.groups = this.groups.sort((a, b) => {
			if (a.name && !b.name)
				return 1;
			if (!a.name && b.name)
				return -1;
			if (!a.name && !b.name)
				return 0;
			return a.name!.toLowerCase().localeCompare(b.name!.toLowerCase());
		})
			.map(g => <auth.Group>{
				name: g.name,
				permissions: g.permissions,
				moduleName: this.getModuleName(g.permissions)
			});

		if (!this.allGroups.length) {
			this.allGroups = this.groups;
			this.attachVueFilterSearch();
		}

		for (const g of this.groups) {
			const { name, moduleName } = g;

			// we do not want to add the admin and enabled groups to the list since
			// we dont want the user to add additional permissions to them
			if (name !== "admin" && name !== "enabled") {
				this.tableGroup.create({
					groupname: name,
					modulename: moduleName
				});
			}
		}
	}

	private attachVueFilterSearch(): void {
		const _self = this;

		const vue = new Vue({
			template: `<filter-search
							:data="allGroups"
							:fields="['name', 'moduleName']"
							placeholder="Search groups"
							@visible="doFilterFields"
							:debounceTime=250
							style="width: 20%; float: right;"
						/>`,
			name: 'filterSearchWrapper',
			el: `#${this.parentId}-group-search`,
			components: {
				'filter-search': FilterSearch
			},
			data() {
				return {
					allGroups: _self.allGroups
				};
			},
			methods: {
				doFilterFields(visibleGroups) {
					_self.groups = visibleGroups;
					_self.parentCtl.css("display", "flex");

					_self.createGroupTable();
					_self.setGroupGrid();
					_self.attachGroupEvents();
				}
			}
		});
	}

	/**
	 * get the module name of the group
	 */
	private getModuleName(permissions: auth.Permission[]): string {
		let moduleNames: string[] = [];
		let moduleName = "";

		// groups are supposed to only have one module associated to them by means of the
		// permissions that gets assigned to them, this is just a sense check,

		for (const p of permissions) {
			if (moduleNames.indexOf(p.module.toString()) === -1)
				moduleNames.push(p.module.toString());
		}

		moduleName = moduleNames
			.sort((a, b) => a.localeCompare(b))
			.join(", ");

		return moduleName;
	}

	private setTableStructure(): void {
		// create the table in the collection
		this.tableGroup = this.authGroupCollection.tableByName("tabgroup", true)!;

		// set the fields on the table
		this.tableGroup.type.setup("id", "groupname", "modulename");
		this.tableGroup.type.keyIsUuid = true;

		// set the field types and aliases
		this.tableGroup.type.fields[1].alias = "Group Name";
		this.tableGroup.type.fields[1].fieldType = "text";
		this.tableGroup.type.fields[2].alias = "Module";
		this.tableGroup.type.fields[2].fieldType = "text";
	}

	/**
	 * set the grid using the browser store table
	 */
	private setGroupGrid() {

		if (this.tableGroup) {

			this.resize();

			this.gridGroup = new IdataGrid(`${this.parentId}-group`,
				undefined,
				(<IMaptoolContext>{}),
				"",
				[this.tableGroup],
				["groupname", "modulename"],
				undefined,
				200,
				[],
				undefined,
				{ hideCloseButton: true, isExportGroupsEnabled: true, exportFileName: "AuthGroups", baseURL: "/auth2/exportgroups" },
				{ includeBelongsToTable: true, hideSort: false });

			this.gridGroup.show();
		}
	}

	resize() {

		const width = $id(`${this.parentId}-group`).parent().parent().parent().width() || 0;
		const height = $id(`${this.parentId}-group`).parent().parent().parent().height() || 0;

		$id(`${this.parentId}-group`).width(width - 22);
		$id(`${this.parentId}-group`).height(height - 92);

	}

	private attachGroupEvents() {
		const f = (arg: idata.Record[]) => {
			// get the name from the selected grid item
			const selectedGroupName = arg[0].get(1);
			// get the group from the group collection( the grid item does not have the permissions)
			let group = this.groups.find(g => g.name === selectedGroupName);
			if (!group)
				return;

			this.selectedGroup = new auth.Group(group.name, group.permissions, group.moduleName);

			// set the toolbar
			if (auth.hasPermission(auth.Permissions.admin)) {
				this.flatButtonControl.changeButtonState(FlatButtonAuthConst.Edit, FlatButtonState.ENABLED);
				this.flatButtonControl.changeButtonState(FlatButtonAuthConst.Delete, FlatButtonState.ENABLED);
			}
		};

		this.gridGroup.onSelect.unsubscribe(f);
		this.gridGroup.onSelect.subscribe(f);
	}
}
