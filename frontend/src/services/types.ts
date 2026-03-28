// ─── Shared types mirroring Go JSON structs ──────────────────────────────────

export enum AuthUserType {
  IMQS = 0,
  LDAP = 1,
  OAuth = 2,
  MSAAD = 3,
}

export function authUserTypeFromNumber(n: number): AuthUserType {
  switch (n) {
    case 1: return AuthUserType.LDAP;
    case 2: return AuthUserType.OAuth;
    case 3: return AuthUserType.MSAAD;
    default: return AuthUserType.IMQS;
  }
}

export function authUserTypeLabel(t: AuthUserType): string {
  switch (t) {
    case AuthUserType.LDAP:  return 'LDAP';
    case AuthUserType.OAuth: return 'OAuth';
    case AuthUserType.MSAAD: return 'MSAAD';
    default:                 return 'IMQS';
  }
}

/** Raw JSON shape returned by GET /userobjects */
export interface RawUser {
  UserId: number;   // int64 in Go — arrives as a JSON number, not a string
  Email: string;
  Username: string;
  Name: string;
  Surname: string;
  Mobile: string;
  Telephone: string;
  Remarks: string;
  Created: string;
  CreatedBy: string;
  Modified: string;
  ModifiedBy: string;
  Archived: boolean;
  AccountLocked: boolean;
  AuthUserType: number;
  Groups: string[];
  LastLogin: string;
  EnabledDate: string;
  DisabledDate: string;
}

/** Raw JSON shape returned by GET /groups */
export interface RawGroup {
  Name: string;
  Roles: string[];
  ID: string;
}

/** Raw JSON shape returned by GET /check or POST /login */
export interface CheckResponse {
  UserId: string;
  Identity: string;
  Email: string;
  Username: string;
  Roles: string[];
  InternalUUID: string;
}

/** Query params for PUT /create_user and POST /update_user */
export interface UserPostData {
  userid?: string;
  email: string;
  username?: string;
  firstname: string;
  lastname: string;
  mobilenumber: string;
  telephonenumber?: string;
  remarks?: string;
  password?: string;
  authusertype?: string;
}

/** Shape of GET /dynamic_permissions response */
export interface DynamicPermissionsResponse {
  dynamic?: Array<{
    id: string;
    name: string;
    friendly: string;
    description: string;
    module: string;
  }>;
  disable?: string[];
  relabel?: Array<{
    id: string;
    name: string;
    friendly: string;
    description: string;
  }>;
}

export interface OAuthProvider {
  Name: string;
  LoginURL: string;
}

