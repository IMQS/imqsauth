// ─── Auth module registry ─────────────────────────────────────────────────────
// Mirrors the Go PermissionsTable module names.

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
  }
}

export interface ModuleOption {
  id: string;
  value: string;
}

/** Returns all registered modules as selectable options, sorted by label. */
export function allModuleOptions(): ModuleOption[] {
  return Object.entries(AuthModule)
    .map(([id, value]) => ({ id, value }))
    .sort((a, b) => a.value.localeCompare(b.value));
}

