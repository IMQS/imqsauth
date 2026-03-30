// ─── Auth module registry ─────────────────────────────────────────────────────
// Mirrors the Go PermissionsTable module names.

import { ref } from 'vue';

/** Bumped whenever a new module is registered so computed() properties re-evaluate. */
export const modulesVersion = ref(0);

export const AuthModule: Record<string, string> = {
  ASSETS:                  'Assets',
  COGTA:                   'COGTA',
  CONDITION_ASSESSMENT:    'Condition Assessment',
  DEVELOPMENT_CONTROL:     'Development Control',
  DOCUMENT_EXPLORER:       'Document Explorer',
  ELECTRICITY_DEMAND:      'Electricity Demand',
  ELECTRICITY_DEMO:        'Electricity Demo',
  ELECTRICITY_RP:          'Electricity RP',
  ELECTRICITY:             'Electricity',
  ENERGY:                  'Energy',
  FACILITIES:              'Facilities',
  GLOBAL:                  'Global',
  IMPORTER:                'Importer',
  IMQS:                    'IMQS',
  INDIGENT:                'Indigent',
  LAND_USE:                'Land Use',
  LEASING:                 'Leasing',
  MAINTENANCE_MANAGEMENT:  'Maintenance Management',
  METER_MAINTENANCE:       'Meter Maintenance',
  MODULE_ACCESS:           'Module Access',
  PCS:                     'PCS',
  PROPERTIES_AND_BUILDINGS:'Properties and Buildings',
  RESOURCE_MANAGER:        'Resource Manager',
  REVENUE_ENHANCEMENT:     'Revenue Enhancement',
  ROAD_SIGNS:              'Road Signs',
  ROADS:                   'Roads',
  SEWER_PRP:               'Sewer PRP',
  SEWER:                   'Sewer',
  STORMWATER:              'Stormwater',
  TELCOS:                  'Telcos',
  THEME_EDITOR:            'Theme Editor',
  WATER_DEMAND:            'Water Demand',
  WATER_PRP:               'Water PRP',
  WATER:                   'Water',
  WAYLEAVE:                'Wayleave',
  WIP:                     'WIP',
};

/** Tracks modules added dynamically from the server */
export const DynamicModules: string[] = [];

export function authModuleExists(moduleName: string): boolean {
  return Object.values(AuthModule).some(v => v === moduleName);
}

export function registerDynamicModule(key: string, value: string): void {
  if (!AuthModule[key]) {
    AuthModule[key] = value;
    DynamicModules.push(key);
    modulesVersion.value++;
  }
}

export interface ModuleOption {
  id: string;
  value: string;
}

/** Returns all registered modules as selectable options, sorted by label.
 *  Reads modulesVersion so that Vue computed() re-evaluates when new modules are registered. */
export function allModuleOptions(): ModuleOption[] {
  void modulesVersion.value; // reactive dependency
  return Object.entries(AuthModule)
    .map(([id, value]) => ({ id, value }))
    .sort((a, b) => a.value.localeCompare(b.value));
}
