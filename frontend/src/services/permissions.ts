// ─── Permissions registry ─────────────────────────────────────────────────────

import { ref } from 'vue';
import { AuthModule, authModuleExists, DynamicModules, registerDynamicModule } from './modules';
import type { DynamicPermissionsResponse } from './types';

/** Bumped whenever the permissions registry changes so computed() properties re-evaluate. */
export const permissionsVersion = ref(0);
function bumpVersion() { permissionsVersion.value++; }

export class Permission {
  constructor(
    public readonly id: string,
    public readonly name: string,
    public friendlyName: string,
    public description: string,
    public readonly module: string,
  ) {
    if (!authModuleExists(module))
      throw new Error(`Permission '${name}': unknown module '${module}'`);
  }
}

function p(id: string, name: string, friendly: string, desc: string, mod: string): Permission {
  return new Permission(id, name, friendly, desc, mod);
}

// ---------------------------------------------------------------------------
// Core / Global
// ---------------------------------------------------------------------------
export const Permissions: Record<string, Permission> = {
  admin:        p('1',  'admin',        'Administrator', 'Super-user who can control all aspects of the auth system', AuthModule.GLOBAL),
  enabled:      p('2',  'enabled',      'Enabled',       'User is allowed to use the system', AuthModule.GLOBAL),
  bulkSms:      p('4',  'bulkSms',      'Bulk SMS',      'User is allowed to send SMS messages', AuthModule.GLOBAL),
  reportCreator:p('200','reportCreator','Report Creator','Can create reports', AuthModule.GLOBAL),
  reportViewer: p('201','reportViewer', 'Report Viewer', 'Can view reports', AuthModule.GLOBAL),
  importer:     p('300','importer',     'Importer',      'User is allowed to handle data imports', AuthModule.GLOBAL),
  fileDrop:     p('301','fileDrop',     'File Drop',     'User is allowed to drop files onto IMQS Web', AuthModule.GLOBAL),
  importsModuleAccess: p('302','importsModuleAccess','Importer Module','Grants user access to the importer module', AuthModule.IMPORTER),
};

export const permissionsArray: Permission[] = Object.values(Permissions);

export function getPermissionById(id: string): Permission | undefined {
  return permissionsArray.find(p => p.id === id);
}

export function getPermissionByName(name: string): Permission | undefined {
  return Permissions[name];
}

/**
 * Apply dynamic permissions returned by GET /dynamic_permissions.
 */
export function applyDynamicPermissions(data: DynamicPermissionsResponse): void {
  // Add new dynamic permissions
  if (data.dynamic) {
    for (const perm of data.dynamic) {
      // Dynamic permissions from config are expected to use high IDs (≥ 15000).
      // Skip anything below that threshold to avoid overwriting static permissions.
      const numericId = parseInt(perm.id, 10);
      if (!isNaN(numericId) && numericId < 15000) continue;

      let modValue: string | undefined;
      for (const [, v] of Object.entries(AuthModule)) {
        if (v.toUpperCase() === perm.module.toUpperCase()) { modValue = v; break; }
      }
      if (!modValue && perm.module) {
        // Register module using original casing as value (e.g. "HashService")
        const moduleKey = perm.module.toUpperCase().replace(/\s+/g, '_');
        registerDynamicModule(moduleKey, perm.module);
        modValue = perm.module;
      }
      if (!modValue) continue;
      // Dynamic config permissions always win — remove any stale static entry first
      const existing = Permissions[perm.name];
      if (existing) {
        const idx = permissionsArray.indexOf(existing);
        if (idx !== -1) permissionsArray.splice(idx, 1);
        delete Permissions[perm.name];
      }
      const newPerm = new Permission(perm.id, perm.name, perm.friendly, perm.description, modValue);
      Permissions[perm.name] = newPerm;
      permissionsArray.push(newPerm);
    }
  }
  // Disable permissions
  if (data.disable) {
    for (const permName of data.disable) {
      if (!Permissions[permName]) continue;
      delete Permissions[permName];
      const idx = permissionsArray.findIndex(p => p.name === permName);
      if (idx !== -1) permissionsArray.splice(idx, 1);
    }
  }
  // Relabel permissions
  if (data.relabel) {
    for (const perm of data.relabel) {
      const current = Permissions[perm.name];
      if (!current || perm.id !== current.id) continue;
      current.friendlyName = perm.friendly;
      current.description  = perm.description;
    }
  }
  bumpVersion();
}

/** Permissions grouped by module name.
 *  Reads permissionsVersion so that Vue computed() re-evaluates when the registry changes. */
export function permissionsByModule(): Map<string, Permission[]> {
  void permissionsVersion.value; // reactive dependency
  const m = new Map<string, Permission[]>();
  for (const perm of permissionsArray) {
    const arr = m.get(perm.module) ?? [];
    arr.push(perm);
    m.set(perm.module, arr);
  }
  return m;
}

// Map from lowercase permission name suffix → module value.
// Mirrors Go's PermissionModuleMap, keyed by the lowercase moduleaccess name.
const moduleAccessNames: Record<string, string> = {
  assetsmoduleaccess:                  AuthModule.ASSETS,
  cogtamoduleaccess:                   AuthModule.COGTA,
  conditionassessmentmoduleaccess:     AuthModule.CONDITION_ASSESSMENT,
  documentexplorermoduleaccess:        AuthModule.DOCUMENT_EXPLORER,
  electricitymoduleaccess:             AuthModule.ELECTRICITY,
  electricitydemandmoduleaccess:       AuthModule.ELECTRICITY_DEMAND,
  electricitydemomoduleaccess:         AuthModule.ELECTRICITY_DEMO,
  electricityrpmoduleaccess:           AuthModule.ELECTRICITY_RP,
  energymoduleaccess:                  AuthModule.ENERGY,
  facilitiesmoduleaccess:              AuthModule.FACILITIES,
  importsmoduleaccess:                 AuthModule.IMPORTER,
  indigentmoduleaccess:                AuthModule.INDIGENT,
  landusemoduleaccess:                 AuthModule.LAND_USE,
  maintenancemanagementmoduleaccess:   AuthModule.MAINTENANCE_MANAGEMENT,
  metermaintenancemoduleaccess:        AuthModule.METER_MAINTENANCE,
  pcsmoduleaccess:                     AuthModule.PCS,
  propertiesandbuildingsmoduleaccess:  AuthModule.PROPERTIES_AND_BUILDINGS,
  revenueenhancementmoduleaccess:      AuthModule.REVENUE_ENHANCEMENT,
  resourcemanagermoduleaccess:         AuthModule.RESOURCE_MANAGER,
  roadSignsmoduleaccess:               AuthModule.ROAD_SIGNS,
  roadsignsmoduleaccess:               AuthModule.ROAD_SIGNS,
  roadsmoduleaccess:                   AuthModule.ROADS,
  sewermoduleaccess:                   AuthModule.SEWER,
  sewerprpmoduleaccess:                AuthModule.SEWER_PRP,
  stormwatermoduleaccess:              AuthModule.STORMWATER,
  telcosmoduleaccess:                  AuthModule.TELCOS,
  themeeditormoduleaccess:             AuthModule.THEME_EDITOR,
  watermoduleaccess:                   AuthModule.WATER,
  waterdemandmoduleaccess:             AuthModule.WATER_DEMAND,
  waterprpmoduleaccess:                AuthModule.WATER_PRP,
  wayleavemoduleaccess:                AuthModule.WAYLEAVE,
  wipmoduleaccess:                     AuthModule.WIP,
  developmentcontrolmoduleaccess:      AuthModule.DEVELOPMENT_CONTROL,
  leasingmoduleaccess:                 AuthModule.LEASING,
};

// Prefix → module for non-moduleaccess permissions
const prefixToModule: Array<[string, string]> = [
  ['pcs',       AuthModule.PCS],
  ['newmmrm',   AuthModule.RESOURCE_MANAGER],
  ['newmmim',   AuthModule.METER_MAINTENANCE],
  ['newmmil',   AuthModule.MAINTENANCE_MANAGEMENT],
  ['newmmtc',   AuthModule.MAINTENANCE_MANAGEMENT],
  ['newmmfi',   AuthModule.MAINTENANCE_MANAGEMENT],
  ['newmmdm',   AuthModule.MAINTENANCE_MANAGEMENT],
  ['newmmsetup',AuthModule.MAINTENANCE_MANAGEMENT],
  ['newmmclock',AuthModule.MAINTENANCE_MANAGEMENT],
  ['newmm',     AuthModule.MAINTENANCE_MANAGEMENT],
  ['mmwm',      AuthModule.MAINTENANCE_MANAGEMENT],
  ['mmsewer',   AuthModule.SEWER],
  ['mmroads',   AuthModule.ROADS],
  ['mmsolid',   AuthModule.MAINTENANCE_MANAGEMENT],
  ['mmwater',   AuthModule.WATER],
  ['mm',        AuthModule.MAINTENANCE_MANAGEMENT],
  ['wmm',       AuthModule.METER_MAINTENANCE],
  ['wip',       AuthModule.WIP],
  ['energy',    AuthModule.ENERGY],
  ['devcon',    AuthModule.DEVELOPMENT_CONTROL],
  ['leasing',   AuthModule.LEASING],
  ['themeeditor',AuthModule.THEME_EDITOR],
  ['wayleave',  AuthModule.WAYLEAVE],
  ['hydro',     AuthModule.WATER],
  ['imqsdeveloper', AuthModule.GLOBAL],
  ['report',    AuthModule.GLOBAL],
  ['importer',  AuthModule.IMPORTER],
  ['imports',   AuthModule.IMPORTER],
  ['filedrop',  AuthModule.GLOBAL],
  ['bulksms',   AuthModule.GLOBAL],
];

function inferModule(name: string): string {
  const lower = name.toLowerCase();
  // Check exact moduleaccess map first
  if (moduleAccessNames[lower]) return moduleAccessNames[lower];
  // Check prefix map
  for (const [prefix, mod] of prefixToModule) {
    if (lower.startsWith(prefix)) return mod;
  }
  return AuthModule.GLOBAL;
}

/**
 * Bootstrap the permissions registry from the full static PermissionsTable
 * returned by GET /groups_perm_names ({ "id": "name" }).
 * Skips IDs already registered (the 8 hardcoded ones).
 */
export function loadStaticPermissions(table: Record<string, string>): void {
  for (const [idStr, name] of Object.entries(table)) {
    if (permissionsArray.some(p => p.id === idStr)) continue;
    const module = inferModule(name);
    // Ensure module is registered (handles any unknown ones gracefully)
    if (!authModuleExists(module)) {
      registerDynamicModule(module.toUpperCase().replace(/\s+/g, '_'), module);
    }
    try {
      const perm = new Permission(idStr, name, name, '', module);
      Permissions[name] = perm;
      permissionsArray.push(perm);
    } catch { /* skip any that still fail */ }
  }
  bumpVersion();
}

